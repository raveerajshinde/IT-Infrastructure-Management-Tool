"""Ansible execution via ansible-runner in isolated, per-job private data directories.

Isolation: each job gets a fresh 0700 temp directory containing a generated inventory
(credentials decrypted only for the duration of the run) and is removed afterwards.
Only playbooks from the server-side catalogue below can run, with validated variables.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ValidationFailed
from app.core.timeutil import utcnow
from app.drivers import validators as v
from app.models import Credential, Device, Job
from app.services import audit, secrets


class _P(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LinuxPkgVars(_P):
    packages: list[v.PackageName] = Field(min_length=1, max_length=50)
    state: Literal["present", "latest", "absent"] = "present"


class ServiceVars(_P):
    service_name: v.ServiceName


class LinuxMaintVars(_P):
    upgrade: bool = False
    autoremove: bool = True
    reboot_if_required: bool = False


class LinuxBaselineVars(_P):
    disable_root_ssh: bool = True
    disable_password_ssh: bool = False
    enable_firewall: bool = True
    allowed_tcp_ports: list[v.Port] = Field(default_factory=lambda: [22])


class WinPkgVars(_P):
    package_path: str = Field(pattern=r"^\\\\[A-Za-z0-9.\-_]+\\[A-Za-z0-9.\-_ $\\]+\.(msi|exe)$")
    product_id: str = Field(pattern=r"^\{?[A-Fa-f0-9\-]{36}\}?$")
    arguments: str = Field("", pattern=r"^[A-Za-z0-9 /=_.\-\"]*$", max_length=300)


class WinShareVars(_P):
    share_name: v.ShareName
    share_path: v.WinPath
    full_access: list[v.Principal] = Field(default_factory=list)
    change_access: list[v.Principal] = Field(default_factory=list)
    read_access: list[v.Principal] = Field(default_factory=list)


class WinBaselineVars(_P):
    disable_smb1: bool = True
    enable_firewall: bool = True
    audit_logon_events: bool = True


PLAYBOOKS: dict[str, dict] = {
    "linux_packages.yml": {"vars": LinuxPkgVars, "category": "linux", "title": "Install/remove packages"},
    "linux_restart_service.yml": {"vars": ServiceVars, "category": "linux", "title": "Restart service"},
    "linux_maintenance.yml": {"vars": LinuxMaintVars, "category": "linux", "title": "Linux maintenance"},
    "linux_security_baseline.yml": {"vars": LinuxBaselineVars, "category": "linux", "title": "Linux security baseline"},
    "windows_install_software.yml": {"vars": WinPkgVars, "category": "windows", "title": "Install software (MSI/EXE from share)"},
    "windows_restart_service.yml": {"vars": ServiceVars, "category": "windows", "title": "Restart service"},
    "windows_create_share.yml": {"vars": WinShareVars, "category": "windows", "title": "Create folder and SMB share"},
    "windows_security_baseline.yml": {"vars": WinBaselineVars, "category": "windows", "title": "Windows security baseline"},
}


def validate_playbook_params(playbook: str | None, params: dict) -> dict:
    meta = PLAYBOOKS.get(playbook or "")
    if not meta:
        raise ValidationFailed(f"Playbook '{playbook}' is not in the approved catalogue")
    try:
        return meta["vars"].model_validate(params).model_dump()
    except Exception as exc:
        raise ValidationFailed(f"Invalid playbook variables: {exc}") from exc


def _host_vars(db: Session, d: Device, keydir: str) -> dict:
    cred = secrets.credential_material(db, db.get(Credential, d.credential_id)) if d.credential_id else {}
    hv: dict = {"ansible_host": d.ip_address}
    if d.platform == "windows":
        hv.update(ansible_connection="psrp", ansible_user=cred.get("username"), ansible_password=cred.get("password"),
                  ansible_port=d.port or 5986, ansible_psrp_auth=cred.get("transport", "negotiate"),
                  ansible_psrp_protocol="https" if cred.get("use_ssl", True) else "http",
                  ansible_psrp_cert_validation="validate" if d.verify_tls else "ignore")
    else:
        hv.update(ansible_connection="ssh", ansible_user=cred.get("username"), ansible_port=d.port or 22,
                  ansible_become=cred.get("username") != "root", ansible_become_method="sudo")
        if cred.get("private_key"):
            kp = os.path.join(keydir, f"key_{d.id}")
            with open(kp, "w") as fh:
                fh.write(cred["private_key"])
            os.chmod(kp, 0o600)
            hv["ansible_ssh_private_key_file"] = kp
        elif cred.get("password"):
            hv["ansible_password"] = cred["password"]
            hv["ansible_become_password"] = cred["password"]
    return hv


def run_playbook_job(db: Session, job: Job) -> None:
    import ansible_runner

    s = get_settings()
    devs = {e.device_id: db.get(Device, e.device_id) for e in job.executions}
    real = {i: d for i, d in devs.items() if not d.is_simulated}
    for e in job.executions:
        e.status, e.started_at = "running", utcnow()
        if devs[e.device_id].is_simulated:
            e.status, e.output, e.finished_at = "succeeded", f"[SIMULATED] {job.playbook} with {json.dumps(job.params)}", utcnow()
    db.commit()
    if not real:
        return
    os.makedirs(s.ansible_work_dir, exist_ok=True)
    pdd = tempfile.mkdtemp(prefix=f"job{job.id}_", dir=s.ansible_work_dir)
    os.chmod(pdd, 0o700)
    try:
        inv = {"all": {"hosts": {d.hostname: _host_vars(db, d, pdd) for d in real.values()}}}
        os.makedirs(os.path.join(pdd, "inventory"), mode=0o700)
        with open(os.path.join(pdd, "inventory", "hosts.json"), "w") as fh:
            json.dump(inv, fh)
        os.makedirs(os.path.join(pdd, "project"), mode=0o700)
        shutil.copy(os.path.join(s.playbook_dir, job.playbook), os.path.join(pdd, "project", job.playbook))
        r = ansible_runner.run(private_data_dir=pdd, playbook=job.playbook, extravars=job.params,
                               cmdline="--check --diff" if job.check_mode else "--diff", timeout=job.timeout_seconds,
                               quiet=True, envvars={"ANSIBLE_HOST_KEY_CHECKING": "False", "ANSIBLE_NOCOLOR": "1",
                                                    "ANSIBLE_DISPLAY_SKIPPED_HOSTS": "False"})
        stdout = r.stdout.read() if r.stdout else ""
        stats = r.stats or {}
        for e in job.executions:
            d = devs[e.device_id]
            if d.is_simulated:
                continue
            h = d.hostname
            failed = h in (stats.get("failures") or {}) or h in (stats.get("dark") or {})
            changed = (stats.get("changed") or {}).get(h, 0)
            e.status = "failed" if failed or r.status in ("timeout", "canceled") else "succeeded"
            e.output = _host_lines(stdout, h)[-200000:]
            e.result = {"changed": changed, "runner_status": r.status, "rc": r.rc}
            e.verification = f"{changed} task(s) changed" + (" (check mode - nothing applied)" if job.check_mode else "")
            e.error = None if e.status == "succeeded" else ("Unreachable" if h in (stats.get("dark") or {}) else f"Playbook {r.status}")
            e.finished_at = utcnow()
            audit.record(db, "job.execute", actor_name=f"worker:{job.worker_id}", target_type="device", target_id=d.id, target_name=h,
                         device_id=d.id, result="success" if e.status == "succeeded" else "failure",
                         details={"job_id": job.id, "playbook": job.playbook, "changed": changed, "status": e.status})
        db.commit()
    finally:
        shutil.rmtree(pdd, ignore_errors=True)


def _host_lines(stdout: str, host: str) -> str:
    keep, out = False, []
    for ln in stdout.splitlines():
        if ln.startswith(("PLAY ", "TASK ", "RUNNING HANDLER")):
            out.append(ln)
            keep = True
            continue
        if ln.startswith("PLAY RECAP"):
            keep = False
        if keep and (f"[{host}]" in ln or f"{host} " in ln or ln.startswith(" ")):
            out.append(ln)
        elif ln.startswith(host + " ") and ":" in ln:
            out.append(ln)
    return "\n".join(out) or stdout
