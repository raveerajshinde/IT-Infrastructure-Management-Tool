"""Script library: reviewed PowerShell / shell / switch CLI / FortiGate CLI scripts.

Rules that keep this safe:
* Scripts are stored server-side. A run request carries only the script id and parameter values;
  the body that executes is loaded from the database at execution time and must hash to the
  approved content, so nothing typed into a browser at run time is ever executed.
* A script can run only after someone other than its last editor approved that exact content
  (scripts:approve). Any edit of the body, parameters or execution options sends it back for review.
* Parameter values are typed and validated (no newlines or control characters, patterns per type).
  PowerShell receives them as bound parameters, shell scripts as quoted variables, CLI scripts by
  substituting {{name}} after validation - a value can never add a command line.
* Runs are ordinary jobs: RBAC per device, approval policies, maintenance windows, audit, and for
  switches/firewalls a configuration backup before and after.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.core.timeutil import utcnow
from app.drivers.base import render_cli  # noqa: F401 - re-exported for callers
from app.models import Script, User
from app.services import audit, auth

TARGETS = {
    "windows": {"label": "Windows (PowerShell)", "category": "windows", "operation": "windows.script.run"},
    "linux": {"label": "Linux (shell)", "category": "linux", "operation": "linux.script.run"},
    "network": {"label": "Switch / router CLI", "category": "network", "operation": "network.script.run"},
    "fortigate": {"label": "FortiGate CLI script", "category": "firewall", "operation": "firewall.script.run"},
}
SCRIPT_OPS = {t["operation"] for t in TARGETS.values()}
PARAM_TYPES = {"string", "int", "bool", "ipv4", "cidr", "hostname", "interface", "vlan", "choice"}
NAME_RX = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
PLACEHOLDER_RX = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")
MAX_BODY = 65_536
# Network CLI lines that are refused even in reviewed scripts (device-wide destructive / lock-out).
NETWORK_DENY = re.compile(
    r"^\s*(reload|erase|write\s+erase|format|delete\s|crypto\s+key\s+zeroize|no\s+ip\s+ssh|no\s+aaa\s+new-model|"
    r"boot\s+system|config-register|/system\s+(reset-configuration|reboot)|/user\s+remove|factory)", re.I)
FORTI_DENY = re.compile(r"^\s*(execute\s+(factoryreset|formatlogdisk|reboot|shutdown|erase-disk)|exec\s+(factoryreset|reboot))", re.I)
NETWORK_READ_RX = {"mikrotik_routeros": re.compile(r"^/\S.*\bprint\b"), "_default": re.compile(r"^(show|display)\s", re.I)}


def sha(script_or_body, params=None, extra=None) -> str:
    if isinstance(script_or_body, Script):
        s = script_or_body
        return sha(s.body, s.params, {"target": s.target, "mode": s.mode, "risk": s.risk, "root": s.run_as_root, "save": s.save_config,
                                      "timeout": s.timeout_seconds})
    blob = json.dumps({"body": script_or_body, "params": params or [], **(extra or {})}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


# ------------------------------------------------------------------ validation
def _check_params(defs: list[dict]) -> list[dict]:
    if not isinstance(defs, list) or len(defs) > 30:
        raise ValidationFailed("Up to 30 parameters")
    out, seen = [], set()
    for d in defs:
        name = str(d.get("name", "")).strip()
        if not NAME_RX.match(name) or name in seen:
            raise ValidationFailed(f"Parameter name '{name}': lower-case letters, digits and _, unique, starting with a letter")
        seen.add(name)
        typ = d.get("type", "string")
        if typ not in PARAM_TYPES:
            raise ValidationFailed(f"Parameter '{name}': unknown type '{typ}'")
        choices = [str(c) for c in d.get("choices") or []]
        if typ == "choice" and not (1 <= len(choices) <= 50):
            raise ValidationFailed(f"Parameter '{name}': list 1-50 choices")
        for c in choices:
            _validate_value({"name": name, "type": "string"}, c)
        out.append({"name": name, "label": str(d.get("label") or name)[:80], "type": typ, "required": bool(d.get("required", True)),
                    "default": d.get("default"), "choices": choices, "max_length": min(int(d.get("max_length") or 200), 1000),
                    "help": str(d.get("help") or "")[:200]})
    return out


def _check_body(target: str, mode: str, body: str, defs: list[dict], platform_hint: str | None = None) -> None:
    if not body.strip():
        raise ValidationFailed("The script is empty")
    if len(body.encode()) > MAX_BODY:
        raise ValidationFailed("Scripts are limited to 64 KB")
    if "\x00" in body:
        raise ValidationFailed("The script contains a NUL character")
    names = {d["name"] for d in defs}
    if target in ("network", "fortigate"):
        used = set(PLACEHOLDER_RX.findall(body))
        if unknown := used - names:
            raise ValidationFailed(f"Placeholder(s) without a parameter definition: {', '.join(sorted(unknown))}")
        deny = NETWORK_DENY if target == "network" else FORTI_DENY
        for i, line in enumerate(body.splitlines(), 1):
            if deny.search(line):
                raise ValidationFailed(f"Line {i} is not allowed in library scripts: '{line.strip()}' (destructive or would lock InfraPilot out)")
        if target == "network" and mode == "read":
            for i, line in enumerate((ln for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("!")), 1):
                rx = NETWORK_READ_RX.get(platform_hint or "", NETWORK_READ_RX["_default"])
                if not (rx.search(line.strip()) or NETWORK_READ_RX["mikrotik_routeros"].search(line.strip())):
                    raise ValidationFailed(f"Read-only scripts may contain only show/display (or RouterOS print) commands; line {i}: '{line.strip()}'")
    elif target == "linux":
        if re.search(r"\{\{", body):
            raise ValidationFailed("Shell scripts use parameters as variables (\"$name\"), not {{name}} placeholders")
    elif target == "windows":
        if re.search(r"\{\{", body):
            raise ValidationFailed("PowerShell scripts use parameters as variables ($name), not {{name}} placeholders")
        if re.search(r"(?im)^\s*param\s*\(", body):
            raise ValidationFailed("Leave out param(): InfraPilot declares the parameters you define and binds their values")


_TYPE_RX = {
    "hostname": re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"),
    "interface": re.compile(r"^[A-Za-z][A-Za-z0-9/._:-]{0,63}$"),
}


def _validate_value(d: dict, raw):
    typ, name = d.get("type", "string"), d["name"]
    if raw is None or raw == "":
        if d.get("required", True) and d.get("default") in (None, ""):
            raise ValidationFailed(f"'{d.get('label') or name}' is required")
        raw = d.get("default")
        if raw is None or raw == "":
            return "" if typ != "bool" else False
    try:
        if typ == "int":
            v = int(raw)
            if abs(v) > 2**31:
                raise ValueError
            return v
        if typ == "bool":
            return raw if isinstance(raw, bool) else str(raw).lower() in ("1", "true", "yes", "on")
        s = str(raw)
        if re.search(r"[\x00-\x1f\x7f]", s):
            raise ValidationFailed(f"'{d.get('label') or name}' must be a single line without control characters")
        if len(s) > int(d.get("max_length") or 200):
            raise ValidationFailed(f"'{d.get('label') or name}' is too long")
        if typ == "ipv4":
            return str(ipaddress.IPv4Address(s))
        if typ == "cidr":
            return str(ipaddress.IPv4Network(s, strict=False))
        if typ == "vlan":
            v = int(s)
            if not 1 <= v <= 4094:
                raise ValueError
            return v
        if typ == "choice":
            if s not in (d.get("choices") or []):
                raise ValidationFailed(f"'{d.get('label') or name}' must be one of: {', '.join(d.get('choices') or [])}")
            return s
        if typ in _TYPE_RX and not _TYPE_RX[typ].match(s):
            raise ValidationFailed(f"'{d.get('label') or name}' is not a valid {typ}")
        return s
    except ValidationFailed:
        raise
    except (ValueError, TypeError):
        raise ValidationFailed(f"'{d.get('label') or name}' is not a valid {typ}") from None


def validate_values(script: Script, values: dict) -> dict:
    extra = set(values or {}) - {d["name"] for d in script.params}
    if extra:
        raise ValidationFailed(f"Unknown parameter(s): {', '.join(sorted(extra))}")
    return {d["name"]: _validate_value(d, (values or {}).get(d["name"])) for d in script.params}


# ------------------------------------------------------------------ library CRUD
def get(db: Session, sid: int) -> Script:
    s = db.get(Script, sid)
    if not s:
        raise NotFound("Script not found")
    return s


def _apply(s: Script, data: dict) -> None:
    target = data.get("target", s.target)
    if target not in TARGETS:
        raise ValidationFailed(f"Target must be one of: {', '.join(TARGETS)}")
    mode = data.get("mode", s.mode or "change")
    if mode not in ("read", "change"):
        raise ValidationFailed("Mode must be read or change")
    risk = data.get("risk", s.risk or "change")
    if risk not in ("read", "change", "critical"):
        raise ValidationFailed("Risk must be read, change or critical")
    if target == "network" and mode == "read":
        risk = "read"
    elif risk == "read":
        raise ValidationFailed("Only switch scripts in read-only (show) mode can be read risk; others are change or critical")
    defs = _check_params(data.get("params", s.params or []))
    body = data.get("body", s.body or "").replace("\r\n", "\n")
    _check_body(target, mode, body, defs)
    timeout = int(data.get("timeout_seconds", s.timeout_seconds or 300))
    if not 10 <= timeout <= 3600:
        raise ValidationFailed("Timeout must be 10-3600 seconds")
    s.target, s.mode, s.risk, s.params, s.body, s.timeout_seconds = target, mode, risk, defs, body, timeout
    s.run_as_root = bool(data.get("run_as_root", s.run_as_root)) and target == "linux"
    s.save_config = bool(data.get("save_config", s.save_config)) and target == "network" and mode == "change"
    for k in ("name", "description"):
        if k in data and data[k] is not None:
            setattr(s, k, str(data[k]).strip()[:1000 if k == "description" else 150])


def create(db: Session, user: User, data: dict, ip: str | None = None) -> Script:
    if not (data.get("name") or "").strip():
        raise ValidationFailed("Name is required")
    if db.execute(select(Script).where(Script.name == data["name"].strip())).first():
        raise ValidationFailed("A script with that name already exists")
    s = Script(created_by=user.id, updated_by=user.id, status="pending", version=1, body="", params=[])
    _apply(s, data)
    s.sha256 = sha(s)
    db.add(s)
    db.flush()
    audit.record(db, "script.create", actor=user, target_type="script", target_id=s.id, target_name=s.name, ip=ip,
                 details={"target": s.target, "risk": s.risk, "sha256": s.sha256, "body": s.body[:4000], "params": s.params})
    db.commit()
    return s


def update(db: Session, user: User, sid: int, data: dict, ip: str | None = None) -> Script:
    s = get(db, sid)
    if s.status == "retired" and data.get("status") != "pending":
        raise ValidationFailed("Retired scripts cannot be edited")
    old = s.sha256
    if "name" in data and data["name"] and data["name"].strip() != s.name and db.execute(select(Script).where(Script.name == data["name"].strip())).first():
        raise ValidationFailed("A script with that name already exists")
    _apply(s, data)
    s.sha256 = sha(s)
    s.updated_by, s.updated_at = user.id, utcnow()
    changed = s.sha256 != old
    if changed:
        s.version += 1
        s.status, s.approved_by, s.approved_at, s.approved_sha256, s.review_comment = "pending", None, None, None, ""
    audit.record(db, "script.update", actor=user, target_type="script", target_id=s.id, target_name=s.name, ip=ip,
                 details={"version": s.version, "content_changed": changed, "sha256": s.sha256, "body": s.body[:4000] if changed else None})
    db.commit()
    return s


def review(db: Session, user: User, sid: int, approve: bool, comment: str = "", ip: str | None = None) -> Script:
    s = get(db, sid)
    auth.require(db, user, "scripts:approve")
    if s.status not in ("pending", "rejected", "approved"):
        raise ValidationFailed(f"A {s.status} script cannot be reviewed")
    if s.updated_by == user.id:
        raise Forbidden("You cannot approve a script you wrote or last edited - another reviewer must approve it")
    if approve and not comment.strip() and s.risk == "critical":
        raise ValidationFailed("Add a review comment when approving a critical script")
    s.status = "approved" if approve else "rejected"
    s.review_comment = comment.strip()[:1000]
    s.approved_by, s.approved_at = (user.id, utcnow()) if approve else (None, None)
    s.approved_sha256 = s.sha256 if approve else None
    audit.record(db, "script.approve" if approve else "script.reject", actor=user, target_type="script", target_id=s.id, target_name=s.name,
                 ip=ip, details={"version": s.version, "sha256": s.sha256, "comment": comment[:500]})
    db.commit()
    return s


def retire(db: Session, user: User, sid: int, ip: str | None = None) -> Script:
    s = get(db, sid)
    s.status, s.approved_sha256 = "retired", None
    audit.record(db, "script.retire", actor=user, target_type="script", target_id=s.id, target_name=s.name, ip=ip)
    db.commit()
    return s


# ------------------------------------------------------------------ running
def runnable(s: Script) -> bool:
    return s.status == "approved" and s.approved_sha256 == s.sha256


def create_run(db: Session, user: User, sid: int, device_ids: list[int], values: dict, reason: str = "",
               check_mode: bool = False, emergency: bool = False, ip: str | None = None):
    """Create a job that runs an approved script. Device RBAC and approval policies apply as for any change."""
    from app.services import jobs

    s = get(db, sid)
    if not runnable(s):
        raise ValidationFailed("This script has not been approved in its current version")
    vals = validate_values(s, values)
    params = {"script_id": s.id, "script_sha256": s.sha256, "values": vals}
    return jobs.create_operation_job(db, user, operation_id=TARGETS[s.target]["operation"], device_ids=device_ids, params=params,
                                     check_mode=check_mode, reason=reason, emergency=emergency, ip=ip,
                                     title=f"Script: {s.name} (v{s.version})", _script=s)


def load_for_execution(db: Session, params: dict) -> dict:
    """Called by the job executor: resolve and re-verify the script, returning the driver parameters."""
    s = db.get(Script, int(params.get("script_id") or 0))
    if not s:
        raise ValidationFailed("The script no longer exists")
    if not runnable(s) or s.sha256 != params.get("script_sha256"):
        raise ValidationFailed("The script was changed, rejected or retired after this job was created; re-run it from the library")
    return {"script_id": s.id, "script_sha256": s.sha256, "values": validate_values(s, params.get("values") or {}),
            "name": s.name, "body": s.body, "param_defs": s.params, "mode": s.mode, "run_as_root": s.run_as_root,
            "save_config": s.save_config, "timeout_seconds": s.timeout_seconds}
