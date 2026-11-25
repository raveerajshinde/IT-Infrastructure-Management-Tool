"""Parse Group Policy XML reports (Get-GPOReport -ReportType Xml, single GPO or -All) into plain data.

The report schema uses a different namespace prefix per client-side extension (q1:, q2:, ...), so everything
here matches on local element names. Extensions we understand (Security, Registry/Administrative Templates,
Windows Firewall, Advanced Audit) become typed settings; any other extension (Group Policy Preferences,
Scripts, Software Installation, ...) is still listed, flattened, so nothing configured is silently dropped.

Report language: policy display names come from the domain controller's GPMC language. The readable
knowledge base matches English names; other languages still parse but show as "Configured (no baseline)".
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from xml.etree import ElementTree as ET

MAX_XML = 64 * 1024 * 1024
_ENTITY = re.compile(r"<!DOCTYPE|<!ENTITY", re.I)


class GpoXmlError(ValueError):
    pass


@dataclass
class Setting:
    key: str                 # stable identifier used for comparisons, e.g. account:MinimumPasswordLength
    scope: str               # computer | user
    extension: str           # Security | Registry | Windows Firewall | Advanced Audit | <other>
    name: str                # name as shown in the GPO report
    value: Any               # normalised python value
    display: str             # value as text
    path: str = ""           # Administrative Template category path, registry key, ...
    explain: str = ""        # Microsoft's explanation text from the report (Administrative Templates)
    raw_type: str = ""       # Password | Account Lockout | Kerberos | Audit | UserRight | SecurityOption | ...


@dataclass
class Link:
    som_name: str
    som_path: str
    enabled: bool
    enforced: bool


@dataclass
class Gpo:
    guid: str
    name: str
    domain: str
    created: str | None
    modified: str | None
    owner: str
    computer_enabled: bool
    user_enabled: bool
    computer_version: str
    user_version: str
    wmi_filter: str
    links: list[Link] = field(default_factory=list)
    settings: list[Setting] = field(default_factory=list)
    security_filtering: list[str] = field(default_factory=list)
    xml: str = ""

    @property
    def status(self) -> str:
        if self.computer_enabled and self.user_enabled:
            return "Enabled"
        if self.computer_enabled:
            return "User settings disabled"
        if self.user_enabled:
            return "Computer settings disabled"
        return "All settings disabled"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_normalise_for_hash(self.xml).encode()).hexdigest()

    def to_dict(self, with_xml: bool = False) -> dict:
        d = asdict(self)
        d["status"] = self.status
        if not with_xml:
            d.pop("xml", None)
        return d


# ------------------------------------------------------------------ helpers
def _ln(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1]


def _child(el: ET.Element | None, name: str) -> ET.Element | None:
    if el is None:
        return None
    for c in el:
        if _ln(c) == name:
            return c
    return None


def _children(el: ET.Element | None, name: str) -> list[ET.Element]:
    return [c for c in el if _ln(c) == name] if el is not None else []


def _text(el: ET.Element | None, *path: str, default: str = "") -> str:
    cur = el
    for p in path:
        cur = _child(cur, p)
        if cur is None:
            return default
    return (cur.text or "").strip() if cur is not None else default


def _bool(s: str) -> bool | None:
    return {"true": True, "false": False}.get((s or "").strip().lower())


def _num(s: str):
    try:
        return int(s)
    except (TypeError, ValueError):
        try:
            return float(s)
        except (TypeError, ValueError):
            return None


def _normalise_for_hash(xml: str) -> str:
    # ReadTime changes on every export; it is not part of the policy
    return re.sub(r"<(\w+:)?ReadTime>[^<]*</(\w+:)?ReadTime>", "", xml or "")


def _xsi_type(el: ET.Element) -> str:
    for k, v in el.attrib.items():
        if k.endswith("}type") or k == "type":
            return v.split(":", 1)[-1]
    return ""


def _coerce(xml) -> str | bytes:
    """PowerShell/PSRP can return a report as a list of strings (chunks or one document per item)."""
    if isinstance(xml, (list, tuple)):
        parts = [p.decode("utf-8-sig", "replace") if isinstance(p, bytes) else str(p) for p in xml if p is not None]
        return "\n".join(parts)
    if xml is None:
        return ""
    return xml if isinstance(xml, (str, bytes)) else str(xml)


def _secure_parse(xml: str | bytes) -> ET.Element:
    xml = _coerce(xml)
    if isinstance(xml, bytes):
        if len(xml) > MAX_XML:
            raise GpoXmlError("GPO report is larger than 64 MB")
        for enc in ("utf-8-sig", "utf-16"):
            try:
                xml = xml.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            raise GpoXmlError("GPO report is not UTF-8 or UTF-16 text")
    if len(xml) > MAX_XML:
        raise GpoXmlError("GPO report is larger than 64 MB")
    if _ENTITY.search(xml[:4096]) or _ENTITY.search(xml):
        raise GpoXmlError("DTD/entity declarations are not allowed in GPO reports")
    xml = re.sub(r"^\s*<\?xml[^>]*\?>", "", xml.lstrip("﻿"))
    try:
        return ET.fromstring(xml)
    except ET.ParseError as exc:
        raise GpoXmlError(f"Not a valid GPO XML report: {exc}") from exc


# ------------------------------------------------------------------ public API
def parse_report(xml: str | bytes) -> list[Gpo]:
    """Accepts the output of Get-GPOReport -ReportType Xml for one GPO (<GPO> root) or -All (<report> root)."""
    if isinstance(xml, (list, tuple)):
        parts = [p for p in xml if p]
        try:  # one complete document per item (e.g. one report per GPO)
            out = [g for part in parts for g in parse_report(part)]
            if out:
                return out
        except GpoXmlError:
            pass  # chunks of a single document: join them below
    root = _secure_parse(xml)
    if _ln(root) == "GPO":
        gpos = [root]
    else:
        gpos = [e for e in root.iter() if _ln(e) == "GPO" and _child(e, "Identifier") is not None]
    if not gpos:
        raise GpoXmlError("No <GPO> elements found - export with Get-GPOReport -All -ReportType Xml")
    return [_parse_gpo(g) for g in gpos]


def _parse_gpo(g: ET.Element) -> Gpo:
    ident = _child(g, "Identifier")
    guid = _text(ident, "Identifier").strip("{}").lower()
    domain = _text(ident, "Domain")
    sd = _child(g, "SecurityDescriptor")
    owner = _text(_child(sd, "Owner"), "Name") if sd is not None else ""
    comp, user = _child(g, "Computer"), _child(g, "User")
    links = [Link(_text(l, "SOMName"), _text(l, "SOMPath"), _bool(_text(l, "Enabled")) is not False,
                  _bool(_text(l, "NoOverride")) is True) for l in _children(g, "LinksTo")]
    filtering = []
    if sd is not None:
        for p in sd.iter():
            if _ln(p) == "TrusteePermissions":
                std = _child(p, "Standard")
                if std is not None and "Apply" in _text(std, "GPOGroupedAccessEnum") and _text(p, "Type", "PermissionType") != "Deny":
                    filtering.append(_text(_child(p, "Trustee"), "Name"))
    out = Gpo(guid=guid, name=_text(g, "Name"), domain=domain, created=_text(g, "CreatedTime") or None,
              modified=_text(g, "ModifiedTime") or None, owner=owner,
              computer_enabled=_bool(_text(comp, "Enabled")) is not False, user_enabled=_bool(_text(user, "Enabled")) is not False,
              computer_version=f"{_text(comp, 'VersionDirectory') or '0'}/{_text(comp, 'VersionSysvol') or '0'}",
              user_version=f"{_text(user, 'VersionDirectory') or '0'}/{_text(user, 'VersionSysvol') or '0'}",
              wmi_filter=_text(g, "FilterName"), links=links, security_filtering=sorted(set(f for f in filtering if f)),
              xml=ET.tostring(g, encoding="unicode"))
    for scope, sec in (("computer", comp), ("user", user)):
        for ed in _children(sec, "ExtensionData"):
            ext = _child(ed, "Extension")
            ext_name = _text(ed, "Name") or (_xsi_type(ext) if ext is not None else "Unknown")
            if ext is not None:
                out.settings.extend(_parse_extension(scope, ext_name, ext))
    return out


def _parse_extension(scope: str, ext_name: str, ext: ET.Element) -> list[Setting]:
    t = _xsi_type(ext)
    if t == "SecuritySettings":
        return _security(scope, ext)
    if t == "RegistrySettings":
        return _registry(scope, ext)
    if t == "WindowsFirewallSettings":
        return _firewall(scope, ext)
    if t == "AuditSettings":
        return _adv_audit(scope, ext)
    return _generic(scope, ext_name, ext)


# ---- Security settings (account policies, audit, user rights, security options, services, event log)
_RIGHTS_NAME = {
    "SeNetworkLogonRight": "Access this computer from the network", "SeInteractiveLogonRight": "Allow log on locally",
    "SeRemoteInteractiveLogonRight": "Allow log on through Remote Desktop Services", "SeBackupPrivilege": "Back up files and directories",
    "SeRestorePrivilege": "Restore files and directories", "SeDebugPrivilege": "Debug programs", "SeTcbPrivilege": "Act as part of the operating system",
    "SeTakeOwnershipPrivilege": "Take ownership of files or other objects", "SeLoadDriverPrivilege": "Load and unload device drivers",
    "SeImpersonatePrivilege": "Impersonate a client after authentication", "SeShutdownPrivilege": "Shut down the system",
    "SeRemoteShutdownPrivilege": "Force shutdown from a remote system", "SeSecurityPrivilege": "Manage auditing and security log",
    "SeSystemtimePrivilege": "Change the system time", "SeMachineAccountPrivilege": "Add workstations to domain",
    "SeEnableDelegationPrivilege": "Enable computer and user accounts to be trusted for delegation",
    "SeDenyNetworkLogonRight": "Deny access to this computer from the network", "SeDenyInteractiveLogonRight": "Deny log on locally",
    "SeDenyRemoteInteractiveLogonRight": "Deny log on through Remote Desktop Services", "SeDenyBatchLogonRight": "Deny log on as a batch job",
    "SeDenyServiceLogonRight": "Deny log on as a service", "SeServiceLogonRight": "Log on as a service", "SeBatchLogonRight": "Log on as a batch job",
    "SeCreateTokenPrivilege": "Create a token object", "SeAssignPrimaryTokenPrivilege": "Replace a process level token",
    "SeManageVolumePrivilege": "Perform volume maintenance tasks", "SeCreateSymbolicLinkPrivilege": "Create symbolic links",
    "SeTrustedCredManAccessPrivilege": "Access Credential Manager as a trusted caller", "SeLockMemoryPrivilege": "Lock pages in memory",
    "SeSystemEnvironmentPrivilege": "Modify firmware environment values", "SeProfileSingleProcessPrivilege": "Profile single process",
}


def _security(scope: str, ext: ET.Element) -> list[Setting]:
    out: list[Setting] = []
    for el in ext:
        kind = _ln(el)
        if kind == "Account":
            name, typ = _text(el, "Name"), _text(el, "Type")
            if _child(el, "SettingBoolean") is not None:
                v = _bool(_text(el, "SettingBoolean"))
                disp = "Enabled" if v else "Disabled"
            else:
                v = _num(_text(el, "SettingNumber"))
                disp = _text(el, "SettingNumber")
            out.append(Setting(f"account:{name}", scope, "Security", name, v, disp, raw_type=typ))
        elif kind == "Audit":
            name = _text(el, "Name")
            s, f = _bool(_text(el, "SuccessAttempts")) is True, _bool(_text(el, "FailureAttempts")) is True
            disp = "Success and Failure" if s and f else "Success" if s else "Failure" if f else "No auditing"
            out.append(Setting(f"audit:{name}", scope, "Security", name, {"success": s, "failure": f}, disp, raw_type="Audit"))
        elif kind == "UserRightsAssignment":
            name = _text(el, "Name")
            members = sorted({_text(m, "Name") or _text(m, "SID") for m in _children(el, "Member")} - {""})
            out.append(Setting(f"right:{name}", scope, "Security", _RIGHTS_NAME.get(name, name), members,
                               ", ".join(members) if members else "No one", path=name, raw_type="UserRight"))
        elif kind == "SecurityOptions":
            sap = _text(el, "SystemAccessPolicyName")
            keyname = _text(el, "KeyName")
            disp_el = _child(el, "Display")
            disp_name = _text(disp_el, "Name") if disp_el is not None else ""
            if _child(el, "SettingNumber") is not None:
                v = _num(_text(el, "SettingNumber"))
            elif _child(el, "SettingString") is not None:
                v = _text(el, "SettingString")
            elif _child(el, "SettingStrings") is not None:
                v = [(_t.text or "").strip() for _t in _child(el, "SettingStrings") if (_t.text or "").strip()]
            else:
                v = None
            shown = _text(disp_el, "DisplayString") if disp_el is not None else ""
            if not shown and disp_el is not None and _child(disp_el, "DisplayBoolean") is not None:
                shown = "Enabled" if _bool(_text(disp_el, "DisplayBoolean")) else "Disabled"
            if not shown:
                shown = ", ".join(v) if isinstance(v, list) else ("" if v is None else str(v))
            if sap:
                out.append(Setting(f"secopt:{sap}", scope, "Security", disp_name or sap, v, shown, raw_type="SecurityOption"))
            elif keyname:
                out.append(Setting(f"reg:{keyname.lower()}", scope, "Security", disp_name or keyname.rsplit("\\", 1)[-1], v, shown,
                                   path=keyname, raw_type="SecurityOption"))
        elif kind == "SystemServices":
            name, mode = _text(el, "Name"), _text(el, "StartupMode")
            out.append(Setting(f"service:{name.lower()}", scope, "Security", name, mode, mode or "Configured (permissions only)", raw_type="Service"))
        elif kind == "EventLog":
            name, log = _text(el, "Name"), _text(el, "Log")
            v = _num(_text(el, "SettingNumber")) if _child(el, "SettingNumber") is not None else _bool(_text(el, "SettingBoolean"))
            out.append(Setting(f"eventlog:{log}:{name}", scope, "Security", f"{log} log: {name}", v, str(v), raw_type="EventLog"))
        elif kind == "RestrictedGroups":
            g = _text(_child(el, "GroupName"), "Name")
            members = sorted({_text(m, "Name") for m in _children(el, "Member")} - {""})
            out.append(Setting(f"restricted:{g.lower()}", scope, "Security", f"Restricted group: {g}", members,
                               ", ".join(members) or "No members", raw_type="RestrictedGroup"))
        elif kind in ("Registry", "File"):
            p = _text(el, "Path")
            out.append(Setting(f"acl:{kind.lower()}:{p.lower()}", scope, "Security", f"{kind} permissions: {p}", "configured",
                               "Permissions configured", path=p, raw_type="Permissions"))
    return out


# ---- Administrative Templates and raw registry values
def _registry(scope: str, ext: ET.Element) -> list[Setting]:
    out: list[Setting] = []
    for el in ext:
        kind = _ln(el)
        if kind == "Policy":
            name, state, cat = _text(el, "Name"), _text(el, "State"), _text(el, "Category")
            parts: dict[str, Any] = {}
            for sub in el:
                sk = _ln(sub)
                if sk in ("DropDownList", "Numeric", "CheckBox", "EditText", "ListBox", "Text", "MultiText"):
                    sname = _text(sub, "Name")
                    if not sname:
                        continue
                    if sk == "CheckBox":
                        parts[sname] = _text(sub, "State") or "Enabled"
                    elif sk == "DropDownList":
                        parts[sname] = _text(_child(sub, "Value"), "Name") or _text(sub, "Value")
                    elif sk == "Numeric":
                        parts[sname] = _num(_text(sub, "Value"))
                    elif sk == "ListBox":
                        vals = _child(sub, "Value")
                        parts[sname] = [(_text(e, "Data") or _text(e, "Name") or (e.text or "")).strip() for e in vals] if vals is not None else []
                    else:
                        parts[sname] = _text(sub, "Value")
            disp = state + ("" if not parts else " — " + "; ".join(f"{k.rstrip(': ')}: {', '.join(map(str, v)) if isinstance(v, list) else v}" for k, v in parts.items()))
            out.append(Setting(f"policy:{cat.lower()}/{name.lower()}", scope, "Registry", name, {"state": state, **parts}, disp,
                               path=cat, explain=_first_sentences(_text(el, "Explain")), raw_type="AdminTemplate"))
        elif kind == "RegistrySetting":
            kp = _text(el, "KeyPath")
            val = _child(el, "Value")
            vname = _text(val, "Name") if val is not None else ""
            data = None
            if val is not None:
                for c in val:
                    if _ln(c) != "Name":
                        data = _num(c.text) if _ln(c) == "Number" else (c.text or "").strip()
            out.append(Setting(f"regval:{kp.lower()}\\{vname.lower()}", scope, "Registry", f"{kp}\\{vname}" if vname else kp, data,
                               "" if data is None else str(data), path=kp, raw_type="RegistryValue"))
    return out


def _first_sentences(text: str, n: int = 2, limit: int = 600) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    parts = re.split(r"(?<=[.!?])\s", text)
    return " ".join(parts[:n])[:limit]


# ---- Windows Defender Firewall with Advanced Security
def _firewall(scope: str, ext: ET.Element) -> list[Setting]:
    out: list[Setting] = []
    for el in ext:
        kind = _ln(el)
        if kind in ("DomainProfile", "PrivateProfile", "PublicProfile"):
            prof = kind.replace("Profile", "")
            for s in el:
                v = _text(s, "Value") if _child(s, "Value") is not None else (s.text or "").strip()
                b = _bool(v)
                out.append(Setting(f"fw:{prof.lower()}:{_ln(s).lower()}", scope, "Windows Firewall", f"{prof} profile: {_ln(s)}",
                                   b if b is not None else _num(v) if _num(v) is not None else v,
                                   ("Yes" if b else "No") if b is not None else v, raw_type="Firewall"))
        elif kind in ("InboundFirewallRules", "OutboundFirewallRules"):
            name = _text(el, "Name")
            disp = f"{'Allow' if _text(el, 'Action').lower() == 'allow' else 'Block'} {kind[:-13].lower()} " \
                   f"{_text(el, 'Protocol') and 'proto ' + _text(el, 'Protocol')} {_text(el, 'LPort') and 'port ' + _text(el, 'LPort')}".strip()
            out.append(Setting(f"fwrule:{kind[:-13].lower()}:{name.lower()}", scope, "Windows Firewall", f"Firewall rule: {name}",
                               {"action": _text(el, "Action"), "dir": _text(el, "Dir"), "active": _text(el, "Active"), "lport": _text(el, "LPort"),
                                "ra": _text(el, "RA4") or _text(el, "RA6")}, re.sub(r"\s+", " ", disp), raw_type="FirewallRule"))
    return out


# ---- Advanced Audit Policy Configuration
_AUDIT_VAL = {0: "No auditing", 1: "Success", 2: "Failure", 3: "Success and Failure"}


def _adv_audit(scope: str, ext: ET.Element) -> list[Setting]:
    out = []
    for el in ext:
        if _ln(el) == "AuditSetting":
            name, v = _text(el, "SubcategoryName"), _num(_text(el, "SettingValue"))
            out.append(Setting(f"advaudit:{name.lower()}", scope, "Advanced Audit", name, v, _AUDIT_VAL.get(v, str(v)), raw_type="AdvancedAudit"))
    return out


# ---- anything else: flatten leaf values so the content is still visible and comparable
def _generic(scope: str, ext_name: str, ext: ET.Element, limit: int = 400) -> list[Setting]:
    out: list[Setting] = []
    seen: dict[str, int] = {}
    for item in list(ext)[:limit]:
        leaves = []
        for e in item.iter():
            if len(e) == 0 and (e.text or "").strip():
                leaves.append(f"{_ln(e)}={(e.text or '').strip()[:120]}")
        for k, v in item.attrib.items():
            if not k.startswith("{"):
                leaves.append(f"{k}={v[:120]}")
        title = item.attrib.get("name") or _text(item, "Name") or _ln(item)
        text = "; ".join(leaves)[:1500]
        key = f"ext:{ext_name.lower()}:{_ln(item).lower()}:{title.lower()}"
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            key += f"#{seen[key]}"
        out.append(Setting(key, scope, ext_name, f"{ext_name}: {title}", text, text, raw_type="Other"))
    return out


# ------------------------------------------------------------------ gpresult / RSoP
def parse_rsop(xml: str | bytes) -> dict:
    """Parse `gpresult /x` or Get-GPResultantSetOfPolicy XML: which GPOs applied and why others did not."""
    root = _secure_parse(xml)
    out: dict = {"computer": None, "user": None}
    for scope, tag in (("computer", "ComputerResults"), ("user", "UserResults")):
        res = _child(root, tag)
        if res is None:
            continue
        gpos = []
        for g in _children(res, "GPO"):
            link = _child(g, "Link")
            applied = _child(g, "Link") is not None and _text(link, "AppliedOrder") not in ("", "0")
            reasons = []
            if _bool(_text(g, "AccessDenied")):
                reasons.append("Security filtering: the account does not have Read + Apply Group Policy permission")
            if _bool(_text(g, "FilterAllowed")) is False:
                reasons.append(f"WMI filter evaluated to false{(' (' + _text(g, 'FilterName') + ')') if _text(g, 'FilterName') else ''}")
            if _bool(_text(g, "IsValid")) is False:
                reasons.append("GPO is not valid (version mismatch between Active Directory and SYSVOL, or SYSVOL inaccessible)")
            if _bool(_text(g, "Enabled")) is False:
                reasons.append(f"{scope.title()} settings of this GPO are disabled")
            if link is not None and _bool(_text(link, "Enabled")) is False:
                reasons.append("The link is disabled")
            if not applied and not reasons:
                reasons.append("Not applied (empty, or superseded/blocked inheritance; check link scope and inheritance)")
            gpos.append({"name": _text(g, "Name"), "guid": _text(_child(g, "Path"), "Identifier").strip("{}").lower(),
                         "applied": applied and not reasons, "link_path": _text(link, "SOMPath"),
                         "applied_order": _num(_text(link, "AppliedOrder")), "enforced": _bool(_text(link, "NoOverride")) is True,
                         "reasons": reasons})
        errors = []
        for es in _children(res, "ExtensionStatus"):
            if _text(es, "Error") not in ("", "0"):
                errors.append({"extension": _text(es, "Name"), "error_code": _text(es, "Error"),
                               "begin": _text(es, "BeginTime"), "end": _text(es, "EndTime")})
        out[scope] = {"name": _text(res, "Name"), "som": _text(res, "SOM"), "site": _text(res, "Site"),
                      "slow_link": _bool(_text(res, "SlowLink")), "gpos": sorted(gpos, key=lambda x: (not x["applied"], x["applied_order"] or 999)),
                      "security_groups": [_text(s, "Name") for s in _children(res, "SecurityGroup")][:200],
                      "extension_errors": errors}
    out["read_time"] = _text(root, "ReadTime")
    return out


def parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "")[:26])
    except ValueError:
        return None
