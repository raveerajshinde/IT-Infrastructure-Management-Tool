"""Active Directory inventory over LDAPS (read-only) and account reports.

Synchronisation reads users, computers, groups, OUs and domain controllers with a least-privileged service
account (any authenticated domain user can read these attributes; no admin rights are needed). Account
changes (create, disable, unlock, group membership) are NOT made over LDAP: they run as approved Windows
operations on a domain controller so RBAC, approvals and the audit trail apply.

Notes on accuracy
* lastLogonTimestamp is replicated with a 9-14 day delay by design; "inactive" thresholds below 30 days are not reliable.
* "Recently deleted" is detected by comparing synchronisations; objects created and deleted between two syncs are not seen.
"""
from __future__ import annotations

import logging
import ssl
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import delete, func, select, true
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailed
from app.core.timeutil import utcnow
from app.models import AdChange, AdDomain, AdObject, Alert, Credential
from app.services import audit, secrets

log = logging.getLogger("infrapilot.ad")

UAC = {"disabled": 0x2, "lockout": 0x10, "passwd_notreqd": 0x20, "encrypted_text_pwd": 0x80, "server_trust": 0x2000,
       "dont_expire": 0x10000, "trusted_for_delegation": 0x80000, "use_des": 0x200000, "dont_req_preauth": 0x400000,
       "password_expired": 0x800000, "trusted_to_auth_for_delegation": 0x1000000}
# Privileged groups by well-known RID (domain) or SID (builtin)
PRIV_RIDS = {512: "Domain Admins", 518: "Schema Admins", 519: "Enterprise Admins", 520: "Group Policy Creator Owners", 526: "Key Admins", 527: "Enterprise Key Admins"}
PRIV_BUILTIN = {"S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators", "S-1-5-32-549": "Server Operators",
                "S-1-5-32-550": "Print Operators", "S-1-5-32-551": "Backup Operators"}
PRIV_NAMES = {"dnsadmins"}
TIER0 = {"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"}
USER_ATTRS = ["objectGUID", "objectSid", "distinguishedName", "sAMAccountName", "name", "displayName", "userAccountControl", "lastLogonTimestamp",
              "pwdLastSet", "accountExpires", "whenCreated", "whenChanged", "lockoutTime", "memberOf", "adminCount", "mail", "userPrincipalName",
              "description", "servicePrincipalName", "msDS-UserPasswordExpiryTimeComputed", "title", "department", "manager"]
COMPUTER_ATTRS = ["objectGUID", "objectSid", "distinguishedName", "sAMAccountName", "name", "dNSHostName", "userAccountControl", "lastLogonTimestamp",
                  "pwdLastSet", "whenCreated", "whenChanged", "operatingSystem", "operatingSystemVersion", "primaryGroupID", "description", "memberOf"]
GROUP_ATTRS = ["objectGUID", "objectSid", "distinguishedName", "sAMAccountName", "name", "groupType", "member", "memberOf", "description",
               "whenCreated", "whenChanged", "managedBy", "adminCount"]
OU_ATTRS = ["objectGUID", "distinguishedName", "name", "description", "gPLink", "gPOptions", "whenCreated", "whenChanged", "managedBy"]


# ------------------------------------------------------------------ value helpers
def _v(e: dict, k: str, default=None):
    v = e.get(k, default)
    if isinstance(v, list):
        return v[0] if len(v) == 1 else (v if v else default)
    return v


def _list(e: dict, k: str) -> list:
    v = e.get(k)
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _ts(v) -> datetime | None:
    """AD time -> naive UTC. Handles ldap3-formatted datetimes, FILETIME integers and the 'never' sentinels."""
    if v in (None, "", [], 0, "0"):
        return None
    if isinstance(v, datetime):
        if v.tzinfo:
            v = v.astimezone(timezone.utc).replace(tzinfo=None)
        if v.year <= 1601 or v.year >= 9999:
            return None
        return v
    try:
        n = int(v)
    except (TypeError, ValueError):
        if isinstance(v, str) and len(v) >= 14 and v[:14].isdigit():  # generalizedTime 20240101120000.0Z
            return datetime.strptime(v[:14], "%Y%m%d%H%M%S")
        return None
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    return datetime(1601, 1, 1) + timedelta(microseconds=n // 10)


def _guid(v) -> str:
    if isinstance(v, bytes) and len(v) == 16:
        import uuid
        return str(uuid.UUID(bytes_le=v))
    return str(v or "").strip("{}").lower()


def _sid(v) -> str:
    if isinstance(v, bytes):
        rev, cnt = v[0], v[1]
        auth = int.from_bytes(v[2:8], "big")
        subs = [int.from_bytes(v[8 + 4 * i:12 + 4 * i], "little") for i in range(cnt)]
        return "S-" + "-".join([str(rev), str(auth), *map(str, subs)])
    return str(v or "")


def _uac(e: dict) -> int:
    try:
        return int(_v(e, "userAccountControl", 0) or 0)
    except (TypeError, ValueError):
        return 0


def dn_to_canonical(dn: str) -> str:
    parts = [p.split("=", 1) for p in _split_dn(dn)]
    dc = ".".join(v for k, v in parts if k.lower() == "dc")
    rest = [v for k, v in parts if k.lower() != "dc"]
    return "/".join([dc, *reversed(rest)])


def _split_dn(dn: str) -> list[str]:
    out, cur, esc = [], "", False
    for ch in dn:
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            cur += ch
            esc = True
        elif ch == ",":
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parent_dn(dn: str) -> str:
    parts = _split_dn(dn)
    return ",".join(parts[1:])


# ------------------------------------------------------------------ connection
def connect(db: Session, dom: AdDomain):
    from ldap3 import ALL, SIMPLE, Connection, Server, Tls

    if not dom.credential_id:
        raise ValidationFailed("Select a credential (user name + password) for this domain")
    cred = secrets.credential_material(db, db.get(Credential, dom.credential_id))
    user, pw = cred.get("username") or "", cred.get("password") or ""
    if "@" not in user and "\\" not in user and "=" not in user:
        user = f"{user}@{dom.name}"
    tls = Tls(validate=ssl.CERT_REQUIRED if dom.verify_tls else ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT,
              ca_certs_file=(dom.settings or {}).get("ca_file") or None)
    use_ssl = dom.ldap_url.lower().startswith("ldaps://")
    if not use_ssl and not dom.start_tls:
        raise ValidationFailed("Use ldaps:// or enable StartTLS - InfraPilot does not send directory credentials over unencrypted LDAP")
    server = Server(dom.ldap_url, use_ssl=use_ssl, tls=tls, get_info=ALL, connect_timeout=15)
    conn = Connection(server, user=user, password=pw, authentication=SIMPLE, auto_bind=False, read_only=True, receive_timeout=60,
                      raise_exceptions=False, auto_range=True)
    if not conn.open():
        raise ConnectionError(f"Cannot connect to {dom.ldap_url}: {conn.last_error or conn.result}")
    if dom.start_tls and not use_ssl and not conn.start_tls():
        raise ConnectionError(f"StartTLS failed: {conn.result}")
    if not conn.bind():
        desc = (conn.result or {}).get("description", "")
        msg = (conn.result or {}).get("message", "")
        hint = " - check the user name and password" if "invalidCredentials" in desc else ""
        raise ConnectionError(f"LDAP bind failed: {desc} {msg}".strip() + hint)
    return conn


def _search(conn, base: str, flt: str, attrs: list[str], scope="SUBTREE") -> Iterable[dict]:
    from ldap3 import BASE, SUBTREE
    gen = conn.extend.standard.paged_search(base, flt, search_scope=SUBTREE if scope == "SUBTREE" else BASE, attributes=attrs,
                                            paged_size=500, generator=True)
    for e in gen:
        if e.get("type") == "searchResEntry":
            yield {"dn": e.get("dn"), **{k: v for k, v in (e.get("attributes") or {}).items()},
                   **{f"raw:{k}": v for k, v in (e.get("raw_attributes") or {}).items() if k in ("objectGUID", "objectSid")}}


def test(db: Session, dom: AdDomain) -> tuple[bool, str]:
    try:
        conn = connect(db, dom)
        try:
            n = sum(1 for _ in _search(conn, dom.base_dn, "(objectClass=domainDNS)", ["distinguishedName"], scope="BASE"))
            who = conn.extend.standard.who_am_i() or ""
            ok = n == 1
            msg = f"Connected and bound as {who or 'service account'}; base DN found" if ok else f"Bound, but base DN {dom.base_dn} was not found"
        finally:
            conn.unbind()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)[:900]
    dom.last_sync_message = msg if not ok else dom.last_sync_message
    return ok, msg


# ------------------------------------------------------------------ synchronisation
def sync(db: Session, dom: AdDomain, conn=None, actor=None) -> dict:
    """Read the directory and update the inventory. Returns counts and detected changes."""
    started = utcnow()
    own = conn is None
    try:
        conn = conn or connect(db, dom)
        dom_attrs = next(iter(_search(conn, dom.base_dn, "(objectClass=domainDNS)",
                                      ["maxPwdAge", "minPwdLength", "lockoutThreshold", "pwdHistoryLength", "msDS-Behavior-Version",
                                       "ms-DS-MachineAccountQuota", "objectSid", "whenCreated"], scope="BASE")), {})
        domain_sid = _sid(_raw(dom_attrs, "objectSid"))
        users = list(_search(conn, dom.base_dn, "(&(objectCategory=person)(objectClass=user))", USER_ATTRS))
        computers = list(_search(conn, dom.base_dn, "(objectClass=computer)", COMPUTER_ATTRS))
        groups = list(_search(conn, dom.base_dn, "(objectClass=group)", GROUP_ATTRS))
        ous = list(_search(conn, dom.base_dn, "(objectClass=organizationalUnit)", OU_ATTRS))
    except Exception as exc:
        dom.last_sync_at, dom.last_sync_ok, dom.last_sync_message = utcnow(), False, str(exc)[:1000]
        raise
    finally:
        if own and conn is not None:
            try:
                conn.unbind()
            except Exception:  # noqa: BLE001
                pass
    # ---- privileged group membership (recursive, by DN)
    gby_dn = {(_v(g, "distinguishedName") or g["dn"]).lower(): g for g in groups}
    priv_groups: dict[str, str] = {}
    for dn, g in gby_dn.items():
        sid = _sid(_raw(g, "objectSid"))
        rid = int(sid.rsplit("-", 1)[-1]) if sid.startswith("S-1-5-21-") else None
        name = _v(g, "sAMAccountName") or _v(g, "name") or ""
        if sid in PRIV_BUILTIN:
            priv_groups[dn] = PRIV_BUILTIN[sid]
        elif rid in PRIV_RIDS and (not domain_sid or sid.startswith(domain_sid + "-")):
            priv_groups[dn] = PRIV_RIDS[rid]
        elif str(name).lower() in PRIV_NAMES:
            priv_groups[dn] = str(name)
    member_of_priv: dict[str, set[str]] = {}

    def expand(gdn: str, label: str, seen: set[str]):
        g = gby_dn.get(gdn)
        if not g or gdn in seen:
            return
        seen.add(gdn)
        for m in _list(g, "member"):
            ml = str(m).lower()
            member_of_priv.setdefault(ml, set()).add(label)
            if ml in gby_dn:
                expand(ml, label, seen)
    for gdn, label in priv_groups.items():
        expand(gdn, label, set())
    # ---- build rows
    now = utcnow()
    rows: dict[str, dict] = {}
    for u in users:
        dn = _v(u, "distinguishedName") or u["dn"]
        uac = _uac(u)
        groups_priv = sorted(member_of_priv.get(dn.lower(), set()))
        exp = _ts(_v(u, "msDS-UserPasswordExpiryTimeComputed"))
        rows[_guid(_raw(u, "objectGUID"))] = dict(
            kind="user", dn=dn, sam=str(_v(u, "sAMAccountName", "") or ""), name=str(_v(u, "name", "") or ""), display_name=str(_v(u, "displayName", "") or ""),
            enabled=not uac & UAC["disabled"], privileged=bool(groups_priv), locked=bool(_ts(_v(u, "lockoutTime"))),
            pwd_never_expires=bool(uac & UAC["dont_expire"]), last_logon=_ts(_v(u, "lastLogonTimestamp")), pwd_last_set=_ts(_v(u, "pwdLastSet")),
            account_expires=_ts(_v(u, "accountExpires")), when_created=_ts(_v(u, "whenCreated")), when_changed=_ts(_v(u, "whenChanged")), os="",
            attrs={"upn": _v(u, "userPrincipalName"), "mail": _v(u, "mail"), "description": _v(u, "description"), "title": _v(u, "title"),
                   "department": _v(u, "department"), "privileged_groups": groups_priv, "admin_count": _v(u, "adminCount"),
                   "spn": [str(x) for x in _list(u, "servicePrincipalName")][:20], "member_of": [str(x) for x in _list(u, "memberOf")][:300],
                   "pwd_expires": exp.isoformat() if exp else None, "must_change_password": _v(u, "pwdLastSet") in (0, "0"),
                   "flags": [k for k, bit in UAC.items() if uac & bit and k in ("passwd_notreqd", "encrypted_text_pwd", "use_des", "dont_req_preauth",
                                                                               "trusted_for_delegation", "trusted_to_auth_for_delegation", "password_expired")],
                   "ou": dn_to_canonical(parent_dn(dn))})
    for c in computers:
        dn = _v(c, "distinguishedName") or c["dn"]
        uac = _uac(c)
        is_dc = bool(uac & UAC["server_trust"]) or str(_v(c, "primaryGroupID", "")) in ("516", "521")
        rows[_guid(_raw(c, "objectGUID"))] = dict(
            kind="dc" if is_dc else "computer", dn=dn, sam=str(_v(c, "sAMAccountName", "") or ""), name=str(_v(c, "name", "") or ""),
            display_name=str(_v(c, "dNSHostName", "") or ""), enabled=not uac & UAC["disabled"], privileged=is_dc, locked=False,
            pwd_never_expires=bool(uac & UAC["dont_expire"]), last_logon=_ts(_v(c, "lastLogonTimestamp")), pwd_last_set=_ts(_v(c, "pwdLastSet")),
            account_expires=None, when_created=_ts(_v(c, "whenCreated")), when_changed=_ts(_v(c, "whenChanged")),
            os=f"{_v(c, 'operatingSystem', '') or ''} {_v(c, 'operatingSystemVersion', '') or ''}".strip()[:200],
            attrs={"dns": _v(c, "dNSHostName"), "description": _v(c, "description"), "read_only_dc": str(_v(c, "primaryGroupID", "")) == "521",
                   "flags": [k for k, bit in UAC.items() if uac & bit and k in ("trusted_for_delegation", "trusted_to_auth_for_delegation")],
                   "ou": dn_to_canonical(parent_dn(dn))})
    for g in groups:
        dn = (_v(g, "distinguishedName") or g["dn"])
        gt = int(_v(g, "groupType", 0) or 0)
        members = [str(m) for m in _list(g, "member")]
        rows[_guid(_raw(g, "objectGUID"))] = dict(
            kind="group", dn=dn, sam=str(_v(g, "sAMAccountName", "") or ""), name=str(_v(g, "name", "") or ""), display_name="",
            enabled=None, privileged=dn.lower() in priv_groups or dn.lower() in member_of_priv, locked=False, pwd_never_expires=False, last_logon=None, pwd_last_set=None,
            account_expires=None, when_created=_ts(_v(g, "whenCreated")), when_changed=_ts(_v(g, "whenChanged")), os="",
            attrs={"type": "Security" if gt & 0x80000000 else "Distribution", "scope": "Global" if gt & 0x2 else "Domain local" if gt & 0x4 else "Universal" if gt & 0x8 else "Builtin",
                   "members": members[:5000], "member_count": len(members), "description": _v(g, "description"), "managed_by": _v(g, "managedBy"),
                   "privileged_label": priv_groups.get(dn.lower()), "nested_in_privileged": sorted(member_of_priv.get(dn.lower(), set())),
                   "ou": dn_to_canonical(parent_dn(dn))})
    for o in ous:
        dn = _v(o, "distinguishedName") or o["dn"]
        rows[_guid(_raw(o, "objectGUID"))] = dict(
            kind="ou", dn=dn, sam="", name=str(_v(o, "name", "") or ""), display_name=dn_to_canonical(dn), enabled=None, privileged=False, locked=False,
            pwd_never_expires=False, last_logon=None, pwd_last_set=None, account_expires=None, when_created=_ts(_v(o, "whenCreated")),
            when_changed=_ts(_v(o, "whenChanged")), os="",
            attrs={"description": _v(o, "description"), "gp_link": _v(o, "gPLink"), "block_inheritance": str(_v(o, "gPOptions", "0")) == "1",
                   "managed_by": _v(o, "managedBy"), "canonical": dn_to_canonical(dn)})
    rows.pop("", None)
    # ---- upsert + change detection
    existing = {o.guid: o for o in db.execute(select(AdObject).where(AdObject.domain_id == dom.id)).scalars().all()}
    first = not existing
    changes: list[AdChange] = []
    for guid, r in rows.items():
        o = existing.pop(guid, None)
        if o is None:
            o = AdObject(domain_id=dom.id, guid=guid, **{k: v for k, v in r.items()})
            db.add(o)
            if not first:
                changes.append(AdChange(domain_id=dom.id, kind=r["kind"], guid=guid, name=r["sam"] or r["name"], change="created",
                                        details={"dn": r["dn"], "when_created": r["when_created"].isoformat() if r["when_created"] else None}))
            if not first and r["privileged"] and r["kind"] == "user":
                changes.append(AdChange(domain_id=dom.id, kind="user", guid=guid, name=r["sam"], change="privileged_added",
                                        details={"groups": r["attrs"]["privileged_groups"]}))
            continue
        if o.enabled is not None and r["enabled"] is not None and o.enabled != r["enabled"]:
            changes.append(AdChange(domain_id=dom.id, kind=r["kind"], guid=guid, name=r["sam"] or r["name"], change="enabled" if r["enabled"] else "disabled",
                                    details={"dn": r["dn"]}))
        if r["kind"] == "user":
            before, after = set((o.attrs or {}).get("privileged_groups") or []), set(r["attrs"]["privileged_groups"])
            if after - before:
                changes.append(AdChange(domain_id=dom.id, kind="user", guid=guid, name=r["sam"], change="privileged_added", details={"groups": sorted(after - before)}))
            if before - after:
                changes.append(AdChange(domain_id=dom.id, kind="user", guid=guid, name=r["sam"], change="privileged_removed", details={"groups": sorted(before - after)}))
        if r["kind"] == "group" and r["privileged"]:
            mb, ma = set((o.attrs or {}).get("members") or []), set(r["attrs"]["members"])
            if mb != ma:
                changes.append(AdChange(domain_id=dom.id, kind="group", guid=guid, name=r["sam"] or r["name"], change="members_changed",
                                        details={"added": sorted(ma - mb)[:100], "removed": sorted(mb - ma)[:100]}))
        for k, v in r.items():
            setattr(o, k, v)
        o.synced_at = now
    for guid, o in existing.items():
        changes.append(AdChange(domain_id=dom.id, kind=o.kind, guid=guid, name=o.sam or o.name, change="deleted", details={"dn": o.dn}))
        db.delete(o)
    for ch in changes:
        db.add(ch)
    db.flush()
    for ch in changes:
        if ch.change in ("privileged_added", "members_changed"):
            _alert(db, f"ad:{dom.id}:{ch.change}:{ch.guid}:{ch.id}", f"AD privileged change: {ch.name}",
                   f"{dom.name}: {ch.change.replace('_', ' ')} - {ch.details}")
    pol = {"min_pwd_length": _int(_v(dom_attrs, "minPwdLength")), "lockout_threshold": _int(_v(dom_attrs, "lockoutThreshold")),
           "pwd_history": _int(_v(dom_attrs, "pwdHistoryLength")), "max_pwd_age_days": _age_days(_v(dom_attrs, "maxPwdAge")),
           "machine_account_quota": _int(_v(dom_attrs, "ms-DS-MachineAccountQuota")), "functional_level": _int(_v(dom_attrs, "msDS-Behavior-Version")),
           "domain_sid": domain_sid}
    stats = summary_counts(rows.values(), dom.stale_days) | {"policy": pol, "duration_s": round((utcnow() - started).total_seconds(), 1),
                                                             "changes": len(changes)}
    dom.stats = stats
    dom.last_sync_at = dom.last_success_at = utcnow()
    dom.last_sync_ok = True
    dom.last_sync_message = f"{stats['users']} users, {stats['computers']} computers, {stats['groups']} groups, {stats['dcs']} DCs; {len(changes)} change(s)"
    audit.record(db, "ad.sync", actor=actor, actor_name=None if actor else "scheduler", target_type="ad_domain", target_id=dom.id, target_name=dom.name,
                 details={"users": stats["users"], "computers": stats["computers"], "groups": stats["groups"], "changes": len(changes)})
    db.flush()
    return stats


def _raw(e: dict, k: str):
    v = e.get(f"raw:{k}")
    if isinstance(v, list):
        v = v[0] if v else None
    return v if v is not None else _v(e, k)


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _age_days(v) -> int | None:
    if isinstance(v, timedelta):
        return abs(v.days)
    try:
        n = abs(int(v))
        return None if n in (0, 0x8000000000000000) else n // (10_000_000 * 86400)
    except (TypeError, ValueError):
        return None


def _alert(db: Session, fp: str, title: str, message: str) -> None:
    from app.services import monitoring
    if db.execute(select(Alert.id).where(Alert.fingerprint == fp[:200])).first():
        return
    a = Alert(source="ad", severity="warning", title=title[:300], message=message[:2000], fingerprint=fp[:200])
    db.add(a)
    db.flush()
    monitoring._announce(db, a, None)


def summary_counts(rows: Iterable[Any], stale_days: int) -> dict:
    cutoff = utcnow() - timedelta(days=stale_days)
    c = {"users": 0, "enabled_users": 0, "disabled_users": 0, "computers": 0, "groups": 0, "ous": 0, "dcs": 0, "privileged_users": 0,
         "inactive_users": 0, "stale_computers": 0, "pwd_never_expires": 0, "locked": 0}
    for r in rows:
        g = (lambda k: r[k]) if isinstance(r, dict) else (lambda k: getattr(r, k))
        k = g("kind")
        if k == "user":
            c["users"] += 1
            c["enabled_users" if g("enabled") else "disabled_users"] += 1
            if g("privileged"):
                c["privileged_users"] += 1
            if g("enabled") and _inactive(g("last_logon"), g("when_created"), cutoff):
                c["inactive_users"] += 1
            if g("enabled") and g("pwd_never_expires"):
                c["pwd_never_expires"] += 1
            if g("locked"):
                c["locked"] += 1
        elif k == "computer":
            c["computers"] += 1
            if g("enabled") and _inactive(g("last_logon"), g("when_created"), cutoff):
                c["stale_computers"] += 1
        elif k == "dc":
            c["dcs"] += 1
        elif k == "group":
            c["groups"] += 1
        elif k == "ou":
            c["ous"] += 1
    return c


def _inactive(last_logon: datetime | None, created: datetime | None, cutoff: datetime) -> bool:
    if last_logon:
        return last_logon < cutoff
    return bool(created and created < cutoff)


def due_domains(db: Session) -> list[AdDomain]:
    now = utcnow()
    out = []
    for d in db.execute(select(AdDomain).where(AdDomain.enabled == true())).scalars().all():
        if d.sync_interval_hours <= 0:
            continue
        last = d.last_sync_at
        if last is None or last + timedelta(hours=d.sync_interval_hours) <= now:
            if d.last_sync_ok is False and last and last + timedelta(minutes=30) > now:
                continue
            out.append(d)
    return out


def purge(db: Session, dom: AdDomain) -> None:
    db.execute(delete(AdObject).where(AdObject.domain_id == dom.id))
    db.execute(delete(AdChange).where(AdChange.domain_id == dom.id))


# ------------------------------------------------------------------ reports
REPORTS = {
    "users": "All user accounts",
    "inactive-users": "Inactive user accounts",
    "stale-computers": "Stale computer accounts",
    "password-expiry": "Password expiry (next 30 days, expired, never expires)",
    "account-expiry": "Account expiry (next 30 days and expired)",
    "privileged": "Privileged accounts",
    "domain-admins": "Domain Admins / Enterprise Admins / Schema Admins membership",
    "group-membership": "Group membership",
    "risky-accounts": "Accounts with risky settings",
    "recent": "Recently created, modified, disabled and deleted",
    "computers": "All computers",
    "domain-controllers": "Domain controllers",
    "ous": "Organizational units",
}


def report(db: Session, dom: AdDomain, key: str, days: int = 30) -> tuple[list[str], list[list], str]:
    if key not in REPORTS:
        raise ValidationFailed("Unknown AD report")
    q = lambda kind: db.execute(select(AdObject).where(AdObject.domain_id == dom.id, AdObject.kind == kind).order_by(AdObject.sam, AdObject.name)).scalars().all()  # noqa: E731
    now = utcnow()
    cutoff = now - timedelta(days=dom.stale_days)
    fmt = lambda d: d.strftime("%Y-%m-%d") if d else ""  # noqa: E731
    note = ""
    if key == "users":
        head = ["Account", "Display name", "Enabled", "Privileged", "Last logon", "Password last set", "Password never expires", "OU", "Created"]
        rows = [[u.sam, u.display_name, u.enabled, u.privileged, fmt(u.last_logon) or "never", fmt(u.pwd_last_set), u.pwd_never_expires, u.attrs.get("ou"),
                 fmt(u.when_created)] for u in q("user")]
    elif key == "inactive-users":
        note = f"Enabled users with no logon for {dom.stale_days}+ days (lastLogonTimestamp; replicated with up to 14 days delay)."
        head = ["Account", "Display name", "Last logon", "Days inactive", "Privileged", "Created", "OU", "Status"]
        rows = [[u.sam, u.display_name, fmt(u.last_logon) or "never", (now - (u.last_logon or u.when_created)).days if (u.last_logon or u.when_created) else "",
                 u.privileged, fmt(u.when_created), u.attrs.get("ou"), "High" if u.privileged else "Medium"]
                for u in q("user") if u.enabled and _inactive(u.last_logon, u.when_created, cutoff)]
    elif key == "stale-computers":
        note = f"Enabled computer accounts with no logon for {dom.stale_days}+ days."
        head = ["Computer", "DNS name", "Operating system", "Last logon", "Days inactive", "Password last set", "OU"]
        rows = [[c.name, c.display_name, c.os, fmt(c.last_logon) or "never", (now - (c.last_logon or c.when_created)).days if (c.last_logon or c.when_created) else "",
                 fmt(c.pwd_last_set), c.attrs.get("ou")] for c in q("computer") if c.enabled and _inactive(c.last_logon, c.when_created, cutoff)]
    elif key == "password-expiry":
        max_age = (dom.stats or {}).get("policy", {}).get("max_pwd_age_days")
        head = ["Account", "Display name", "Password last set", "Expires", "Days left", "Status"]
        rows = []
        for u in q("user"):
            if not u.enabled:
                continue
            if u.pwd_never_expires:
                rows.append([u.sam, u.display_name, fmt(u.pwd_last_set), "never", "", "Never expires"])
                continue
            exp = datetime.fromisoformat(u.attrs["pwd_expires"]) if u.attrs.get("pwd_expires") else (
                u.pwd_last_set + timedelta(days=max_age) if u.pwd_last_set and max_age else None)
            if exp is None:
                continue
            left = (exp - now).days
            if left <= days:
                rows.append([u.sam, u.display_name, fmt(u.pwd_last_set), fmt(exp), left, "Expired" if left < 0 else "Expiring"])
        note = "Uses msDS-UserPasswordExpiryTimeComputed (includes fine-grained password policies) or the domain maximum password age."
    elif key == "account-expiry":
        head = ["Account", "Display name", "Account expires", "Days left", "Status"]
        rows = [[u.sam, u.display_name, fmt(u.account_expires), (u.account_expires - now).days, "Expired" if u.account_expires < now else "Expiring"]
                for u in q("user") if u.enabled and u.account_expires and u.account_expires - now <= timedelta(days=days)]
    elif key == "privileged":
        head = ["Account", "Display name", "Enabled", "Privileged groups", "Last logon", "Password last set", "Password never expires", "SPN (Kerberoastable)", "Risk"]
        rows = []
        for u in q("user"):
            if not u.privileged:
                continue
            risky = u.pwd_never_expires or bool(u.attrs.get("spn")) or bool(u.enabled and _inactive(u.last_logon, u.when_created, cutoff))
            tier0 = bool(set(u.attrs.get("privileged_groups") or []) & TIER0)
            rows.append([u.sam, u.display_name, u.enabled, ", ".join(u.attrs.get("privileged_groups") or []), fmt(u.last_logon) or "never", fmt(u.pwd_last_set),
                         u.pwd_never_expires, bool(u.attrs.get("spn")), "High" if risky and tier0 else "Medium" if risky else "Low"])
    elif key == "domain-admins":
        head = ["Group", "Member", "Kind", "Enabled", "Last logon"]
        rows = []
        users = {u.dn.lower(): u for u in q("user")}
        for g in q("group"):
            if g.attrs.get("privileged_label") in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"):
                for m in g.attrs.get("members") or []:
                    u = users.get(m.lower())
                    rows.append([g.attrs["privileged_label"], u.sam if u else m, "user" if u else "group/other", u.enabled if u else "", fmt(u.last_logon) if u else ""])
    elif key == "group-membership":
        head = ["Group", "Type", "Scope", "Members", "Privileged", "Description", "OU"]
        rows = [[g.sam or g.name, g.attrs.get("type"), g.attrs.get("scope"), g.attrs.get("member_count"), g.privileged, g.attrs.get("description"), g.attrs.get("ou")]
                for g in q("group")]
    elif key == "risky-accounts":
        head = ["Account", "Kind", "Enabled", "Issue", "Risk", "Recommendation"]
        rows = []
        tips = {"passwd_notreqd": ("Password not required", "High", "Clear the PASSWD_NOTREQD flag and set a password"),
                "encrypted_text_pwd": ("Reversible password encryption", "Critical", "Disable reversible encryption and reset the password"),
                "use_des": ("DES-only Kerberos keys", "High", "Remove 'Use only DES encryption types'"),
                "dont_req_preauth": ("Kerberos pre-authentication disabled (AS-REP roastable)", "High", "Enable Kerberos pre-authentication"),
                "trusted_for_delegation": ("Unconstrained delegation", "High", "Use constrained or resource-based constrained delegation"),
                "trusted_to_auth_for_delegation": ("Protocol transition delegation", "Medium", "Review delegation targets")}
        for o in [*q("user"), *q("computer")]:
            for f in o.attrs.get("flags") or []:
                if f in tips and o.enabled:
                    rows.append([o.sam or o.name, o.kind, o.enabled, tips[f][0], tips[f][1], tips[f][2]])
            if o.kind == "user" and o.enabled and o.privileged and o.attrs.get("spn"):
                rows.append([o.sam, "user", True, "Privileged account with SPN (Kerberoastable)", "High", "Remove the SPN or use a gMSA; use a long random password"])
            if o.kind == "user" and o.enabled and o.privileged and o.pwd_never_expires:
                rows.append([o.sam, "user", True, "Privileged account password never expires", "Medium", "Rotate regularly or use a managed account"])
    elif key == "recent":
        since = now - timedelta(days=days)
        head = ["When", "Account", "Kind", "Event", "Details"]
        rows = [[u.when_created, u.sam or u.name, u.kind, "Created", u.dn] for k in ("user", "computer", "group") for u in q(k)
                if u.when_created and u.when_created >= since]
        rows += [[u.when_changed, u.sam or u.name, u.kind, "Modified", u.dn] for k in ("user", "group") for u in q(k)
                 if u.when_changed and u.when_changed >= since and (not u.when_created or u.when_changed - u.when_created > timedelta(minutes=5))]
        rows += [[c.ts, c.name, c.kind, c.change.replace("_", " ").title(), ", ".join(f"{k}: {v}" for k, v in (c.details or {}).items())[:300]]
                 for c in db.execute(select(AdChange).where(AdChange.domain_id == dom.id, AdChange.ts >= since).order_by(AdChange.id.desc())).scalars().all()]
        rows.sort(key=lambda r: r[0] or datetime.min, reverse=True)
        note = "Created/modified come from whenCreated/whenChanged; disabled, deleted and privileged changes are detected between synchronisations."
    elif key == "computers":
        head = ["Computer", "DNS name", "Operating system", "Enabled", "Last logon", "OU", "Created"]
        rows = [[c.name, c.display_name, c.os, c.enabled, fmt(c.last_logon) or "never", c.attrs.get("ou"), fmt(c.when_created)] for c in q("computer")]
    elif key == "domain-controllers":
        head = ["Domain controller", "DNS name", "Operating system", "Read-only", "Last logon", "OU"]
        rows = [[c.name, c.display_name, c.os, c.attrs.get("read_only_dc"), fmt(c.last_logon), c.attrs.get("ou")] for c in q("dc")]
    else:  # ous
        head = ["OU", "Description", "GPO links", "Block inheritance", "Created"]
        rows = [[o.attrs.get("canonical"), o.attrs.get("description"), (o.attrs.get("gp_link") or "").count("LDAP://"), o.attrs.get("block_inheritance"),
                 fmt(o.when_created)] for o in sorted(q("ou"), key=lambda x: x.attrs.get("canonical") or "")]
    return head, rows, note


def counts(db: Session, dom: AdDomain) -> dict:
    return dict(db.execute(select(AdObject.kind, func.count()).where(AdObject.domain_id == dom.id).group_by(AdObject.kind)).all())
