"""Simulated devices for DEMO MODE ONLY.

The simulator mirrors the operation catalogue of the real driver for the device's
platform (same parameter validation, same risk levels, same approval flow) but never
contacts anything. Every result is prefixed with [SIMULATED] and devices are flagged
is_simulated, which the UI renders with a distinct badge. The API refuses to create
simulated devices when IP_APP_MODE=production.
"""
from __future__ import annotations

import hashlib
import math
import time

from app.drivers.base import ConnectivityResult, Driver, OpResult


def _samples(host: str) -> dict:
    """Plausible, clearly fake rows so the Manage console can be explored in demo mode."""
    return {
        "windows.services.list": [
            {"Name": n, "DisplayName": d, "Status": st, "StartType": t} for n, d, st, t in [
                ("W32Time", "Windows Time", "Running", "Automatic"), ("Spooler", "Print Spooler", "Stopped", "Manual"),
                ("WinRM", "Windows Remote Management", "Running", "Automatic"), ("DNS", "DNS Server", "Running", "Automatic"),
                ("wuauserv", "Windows Update", "Stopped", "Manual"), ("BITS", "Background Intelligent Transfer", "Running", "Automatic")]],
        "windows.processes.list": [{"Id": 1000 + i * 37, "ProcessName": n, "CPUSeconds": c, "MemoryMB": m} for i, (n, c, m) in enumerate(
            [("sqlservr", 5521.4, 4096.2), ("w3wp", 812.0, 512.7), ("svchost", 410.3, 88.1), ("MsMpEng", 300.9, 210.4), ("explorer", 12.2, 95.0)])],
        "windows.localusers.list": [{"Name": "Administrator", "FullName": "", "Enabled": False, "Description": "Built-in account"},
                                    {"Name": "svc_backup", "FullName": "Backup service", "Enabled": True, "Description": "Veeam"}],
        "windows.ad.users.list": [{"SamAccountName": u, "DisplayName": d, "mail": f"{u}@example.local", "Enabled": e, "LockedOut": lk,
                                   "LastLogonDate": "2026-11-10T08:12:00"} for u, d, e, lk in [
            ("jdoe", "John Doe", True, False), ("asmith", "Anna Smith", True, True), ("old.contractor", "Old Contractor", False, False)]],
        "windows.tasks.list": [{"TaskName": "NightlyExport", "TaskPath": "\\", "State": "Ready", "LastTaskResult": 0},
                               {"TaskName": "LegacySync", "TaskPath": "\\", "State": "Disabled", "LastTaskResult": 1}],
        "windows.updates.pending": [{"Title": "2026-11 Cumulative Update for Windows Server", "KB": "KB5049999", "Severity": "Critical", "SizeMB": 812}],
        "windows.software.list": [{"Name": "Microsoft SQL Server 2022", "Version": "16.0.4135.4", "Publisher": "Microsoft"},
                                  {"Name": "7-Zip 24.08", "Version": "24.08", "Publisher": "Igor Pavlov"}],
        "linux.services.list": [{"unit": u, "load": "loaded", "active": a, "sub": sub, "description": d} for u, a, sub, d in [
            ("nginx.service", "active", "running", "A high performance web server"), ("ssh.service", "active", "running", "OpenBSD Secure Shell server"),
            ("cron.service", "active", "running", "Regular background program processing"), ("postfix.service", "failed", "failed", "Postfix Mail Transport Agent"),
            ("docker.service", "inactive", "dead", "Docker Application Container Engine")]],
        "linux.processes.top": [{"pid": 900 + i * 11, "user": u, "cpu_pct": c, "mem_pct": m, "rss_kb": int(m * 40000), "elapsed": "3-02:11:09", "command": cmd}
                                for i, (u, c, m, cmd) in enumerate([("www-data", 12.5, 3.1, "nginx: worker"), ("postgres", 8.0, 12.4, "postgres: writer"),
                                                                      ("root", 1.2, 0.4, "sshd: admin")])],
        "windows.firewall.rules.list": [
            {"DisplayName": n, "Enabled": e, "Direction": "Inbound", "Action": a, "Protocol": pr, "LocalPort": lp, "RemoteAddress": ra, "Profile": pf, "Group": g}
            for n, e, a, pr, lp, ra, pf, g in [
                ("Windows Remote Management (HTTP-In)", "True", "Allow", "TCP", "5985", "Any", "Domain, Private", "Windows Remote Management"),
                ("Remote Desktop - User Mode (TCP-In)", "True", "Allow", "TCP", "3389", "10.0.0.0/255.0.0.0", "Domain", "Remote Desktop"),
                ("SQL Server 1433", "True", "Allow", "TCP", "1433", "10.10.0.0/255.255.0.0", "Domain", "InfraPilot"),
                ("Legacy FTP", "False", "Allow", "TCP", "21", "Any", "Any", "InfraPilot"),
                ("Block SMBv1 from guest VLAN", "True", "Block", "TCP", "445", "192.168.50.0/255.255.255.0", "Any", "InfraPilot")]],
        "linux.firewall.rules": [
            {"number": i, "to": f"{pt}/tcp", "action": a, "direction": "in", "from": src or "Anywhere", "comment": c, "port": pt, "protocol": "tcp",
             "source": src, "ipv6": False, "manageable": True}
            for i, (pt, a, src, c) in enumerate([(22, "allow", None, "ssh"), (443, "allow", None, "web"), (5432, "allow", "10.10.0.0/16", "postgres app tier"),
                                                 (3306, "deny", None, "")], start=1)],
        "linux.users.list": [{"username": "admin", "uid": 1000, "gid": 1000, "comment": "Admin", "home": "/home/admin", "shell": "/bin/bash"},
                             {"username": "deploy", "uid": 1001, "gid": 1001, "comment": "CI deploy", "home": "/home/deploy", "shell": "/bin/bash"}],
        "linux.updates.pending": [{"package": "openssl", "new_version": "3.0.2-0ubuntu1.19", "current": "3.0.2-0ubuntu1.18", "security": True},
                                  {"package": "curl", "new_version": "7.81.0-1ubuntu1.20", "current": "7.81.0-1ubuntu1.19", "security": False}],
        "network.interfaces": [{"name": f"Gi1/0/{i}", "description": d, "status": st, "vlan": vl, "duplex": "a-full", "speed": "a-1000", "type": "10/100/1000BaseTX"}
                               for i, (d, st, vl) in enumerate([("Uplink core", "connected", "trunk"), ("Printer 2F", "connected", "20"),
                                                                ("", "notconnect", "1"), ("Old AP", "disabled", "30")], start=1)],
        "firewall.rules.list": [{"id": i, "name": n, "action": "accept", "enabled": e, "src_zone": "lan", "dst_zone": "wan", "src": s_, "dst": ["all"],
                                 "service": svc, "nat": True, "log": True, "comments": ""} for i, n, e, s_, svc in [
            (1, "LAN to Internet", True, ["LAN_NET"], ["HTTP", "HTTPS", "DNS"]), (2, "Temp vendor access", True, ["all"], ["ALL"]),
            (3, "Legacy FTP", False, ["SRV_NET"], ["FTP"])]],
        "virt.vms": [{"vmid": 100 + i, "name": n, "type": t, "node": "pve1", "status": st, "cpu_pct": c, "mem_pct": m, "maxmem_gb": g, "uptime_h": u}
                     for i, (n, t, st, c, m, g, u) in enumerate([("dc01", "qemu", "running", 4.2, 61.0, 8, 402.5), ("web01", "qemu", "running", 18.9, 44.2, 4, 96.1),
                                                                 ("build-agent", "lxc", "stopped", 0, 0, 2, 0)])],
        "virt.vm.snapshots": [{"snapname": "pre-patch", "description": "Before November patching", "created": "2026-11-01 21:00", "vmstate": False}],
        "virt.hosts": [{"node": "pve1", "status": "online", "cpu_pct": 22.4, "mem_pct": 71.0, "uptime_h": 1210.0}],
        "virt.storage": [{"storage": "local-lvm", "node": "pve1", "status": "available", "used_pct": 63.2, "size_gb": 900.0, "plugin": "lvmthin"}],
    }


class SimulatedDriver(Driver):
    key = "simulated"
    category = "simulated"
    display_name = "Simulated device (demo)"

    def __init__(self, device, credential, timeout=60, snmp_credential=None, real_cls: type[Driver] | None = None):
        super().__init__(device, credential, timeout, snmp_credential)
        self.real_cls = real_cls

    @property
    def ops(self):
        return self.real_cls.operations if self.real_cls else {}

    def _seed(self, salt: str) -> float:
        h = hashlib.sha256(f"{self.device.id}:{salt}".encode()).digest()
        return int.from_bytes(h[:4], "big") / 2**32

    def test_connection(self) -> ConnectivityResult:
        return ConnectivityResult(True, "[SIMULATED] reachable", round(1 + self._seed("lat") * 8, 2),
                                  {"vendor": getattr(self.real_cls, "vendor", "Demo"), "os_name": "Simulated " + getattr(self.real_cls, "display_name", "")})

    def collect_metrics(self) -> dict[str, float]:
        t = time.time() / 600
        base = lambda s, lo, hi: lo + (hi - lo) * (0.5 + 0.5 * math.sin(t + self._seed(s) * 6.28)) * (0.7 + 0.3 * self._seed(s + "x"))  # noqa: E731
        return {"cpu_pct": round(base("cpu", 3, 92), 2), "mem_pct": round(base("mem", 25, 88), 2), "disk_pct": round(base("disk", 30, 93), 2),
                "latency_ms": round(1 + self._seed("lat") * 8, 2)}

    def run(self, op_id: str, params: dict, check_mode: bool = False) -> OpResult:
        if self.real_cls is None:
            return OpResult(status="unsupported", output="[SIMULATED] no driver for platform")
        spec = self.real_cls.get_spec(op_id)
        model = spec.params.model_validate(params or {})
        shown = {k: ("***" if k in spec.secret_params else val) for k, val in model.model_dump().items()}
        if spec.risk == "read" and op_id.endswith("config.backup"):
            cfg = f"! [SIMULATED] configuration of {self.device.hostname}\nhostname {self.device.hostname}\n!\nend\n"
            return OpResult(output=f"[SIMULATED] Captured: running ({len(cfg)} bytes)", config_backups=[("running", cfg)])
        if spec.risk == "read":
            sample = _samples(self.device.hostname).get(op_id)
            if sample is not None:
                return OpResult(output=f"[SIMULATED] {spec.title} on {self.device.hostname}: {len(sample)} row(s) of sample data", data=sample)
            return OpResult(output=f"[SIMULATED] {spec.title} on {self.device.hostname}", data={"simulated": True, "params": shown})
        prefix = "[SIMULATED][check mode] would" if check_mode else "[SIMULATED]"
        backups = []
        if self.real_cls.category in ("network", "firewall") and not check_mode:
            before = f"! simulated config for {self.device.hostname}\nhostname {self.device.hostname}\n"
            after = before + f"! change: {spec.describe(shown)}\n"
            backups = [("running-before", before), ("running", after)]
        return OpResult(output=f"{prefix} {spec.describe(shown)}", data={"simulated": True},
                        verification="[SIMULATED] verification skipped", rollback="[SIMULATED] no rollback required",
                        config_backups=backups)
