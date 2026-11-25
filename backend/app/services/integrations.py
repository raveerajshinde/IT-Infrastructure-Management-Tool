"""External monitoring integrations (Zabbix JSON-RPC, LibreNMS REST). Read-only: hosts + active problems."""
from __future__ import annotations

from sqlalchemy import true

import httpx
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.models import Credential, Integration
from app.services import secrets


def _cred(db: Session, it: Integration) -> dict:
    return secrets.credential_material(db, db.get(Credential, it.credential_id)) if it.credential_id else {}


def _zabbix(db: Session, it: Integration, method: str, params: dict):
    c = _cred(db, it)
    token = c.get("token") or c.get("password")
    url = it.base_url.rstrip("/") + ("" if it.base_url.endswith("api_jsonrpc.php") else "/api_jsonrpc.php")
    headers = {"Content-Type": "application/json-rpc", "Authorization": f"Bearer {token}"}
    r = httpx.post(url, json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1}, headers=headers,
                   verify=it.verify_tls, timeout=20)
    r.raise_for_status()
    body = r.json()
    if "error" in body:
        raise RuntimeError(f"Zabbix: {body['error'].get('data') or body['error'].get('message')}")
    return body["result"]


def _librenms(db: Session, it: Integration, path: str):
    c = _cred(db, it)
    r = httpx.get(it.base_url.rstrip("/") + "/api/v0/" + path, headers={"X-Auth-Token": c.get("token") or c.get("password") or ""},
                  verify=it.verify_tls, timeout=20)
    r.raise_for_status()
    return r.json()


def test(db: Session, it: Integration) -> tuple[bool, str]:
    try:
        if it.kind == "zabbix":
            v = _zabbix(db, it, "host.get", {"countOutput": True})
            msg = f"Connected: {v} hosts visible"
        else:
            v = _librenms(db, it, "devices?type=all")
            msg = f"Connected: {v.get('count', len(v.get('devices', [])))} devices visible"
        ok = True
    except Exception as exc:
        ok, msg = False, str(exc)[:900]
    it.last_test_at, it.last_test_ok, it.last_test_message = utcnow(), ok, msg
    return ok, msg


def problems(db: Session, it: Integration) -> list[dict]:
    if it.kind == "zabbix":
        rows = _zabbix(db, it, "problem.get", {"output": ["eventid", "name", "severity", "clock", "objectid"], "recent": False,
                                               "sortfield": ["eventid"], "sortorder": "DESC", "limit": 500})
        hosts: dict[str, str] = {}
        tids = sorted({p["objectid"] for p in rows if p.get("objectid")})
        if tids:
            for t in _zabbix(db, it, "trigger.get", {"triggerids": tids, "output": ["triggerid"], "selectHosts": ["host"]}):
                hosts[t["triggerid"]] = (t.get("hosts") or [{}])[0].get("host", "")
        sev = {"0": "info", "1": "info", "2": "warning", "3": "warning", "4": "critical", "5": "critical"}
        return [{"id": p["eventid"], "title": p["name"], "severity": sev.get(str(p.get("severity")), "warning"), "since": p.get("clock"),
                 "host": hosts.get(p.get("objectid"), "")} for p in rows]
    rows = _librenms(db, it, "alerts?state=1").get("alerts", [])
    return [{"id": a.get("id"), "title": a.get("rule") or a.get("name") or f"alert {a.get('id')}", "severity": a.get("severity", "warning"),
             "since": a.get("timestamp"), "host": a.get("hostname", "")} for a in rows]


def sync(db: Session, it: Integration) -> str:
    """Import active problems as alerts (source = integration kind); resolve alerts whose problem has cleared."""
    from sqlalchemy import select

    from app.models import Alert, Device

    items = problems(db, it)
    by_name = {d.hostname.lower(): d.id for d in db.execute(select(Device).where(Device.deleted_at.is_(None))).scalars()}
    seen = set()
    for p in items:
        fp = f"int:{it.id}:{p['id']}"
        seen.add(fp)
        a = db.execute(select(Alert).where(Alert.fingerprint == fp, Alert.status != "resolved")).scalar_one_or_none()
        if a:
            a.last_seen_at = utcnow()
            continue
        host = (p.get("host") or "").lower()
        db.add(Alert(source=it.kind, severity=p["severity"] if p["severity"] in ("info", "warning", "critical") else "warning",
                     title=f"[{it.name}] {p['title']}"[:300], message=f"Imported from {it.kind}", fingerprint=fp, device_id=by_name.get(host)))
    for a in db.execute(select(Alert).where(Alert.fingerprint.like(f"int:{it.id}:%"), Alert.status != "resolved")).scalars().all():
        if a.fingerprint not in seen:
            a.status, a.resolved_at = "resolved", utcnow()
    it.last_test_at, it.last_test_ok, it.last_test_message = utcnow(), True, f"{len(items)} active problem(s) imported"
    return it.last_test_message


def sync_all(db: Session) -> None:
    from sqlalchemy import select

    for it in db.execute(select(Integration).where(Integration.enabled == true())).scalars().all():
        try:
            sync(db, it)
        except Exception as exc:
            it.last_test_at, it.last_test_ok, it.last_test_message = utcnow(), False, str(exc)[:900]
    db.commit()
