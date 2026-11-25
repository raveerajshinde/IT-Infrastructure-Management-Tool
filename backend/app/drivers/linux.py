"""Linux server driver (SSH via paramiko).

Commands are built as argument lists from validated parameters and joined with
shlex.join (each argument quoted), so user input cannot alter command structure.
Privileged commands use `sudo -n` when the credential is not root and `become` is set.
Host keys: unknown keys are rejected unless the credential sets `host_key_policy: tofu`,
in which case the first-seen key is pinned in the platform's known_hosts file.
"""
from __future__ import annotations

import io
import json
import os
import re
import shlex
import time
from typing import Literal

from pydantic import Field

from app.core.errors import DeviceConnectionError, Unsupported, ValidationFailed
from app.drivers import validators as v
from app.drivers.base import ScriptRunP, require_library_body, ConnectivityResult, Driver, OpResult, StrictParams, operation

KNOWN_HOSTS = os.environ.get("IP_KNOWN_HOSTS_FILE", "/var/lib/infrapilot/known_hosts")


class CmdResult:
    def __init__(self, rc: int, out: str, err: str):
        self.rc, self.out, self.err = rc, out, err

    @property
    def ok(self):
        return self.rc == 0


# ---------------------------------------------------------------- params
class UnitP(StrictParams):
    unit: v.UnitName


class PkgP(StrictParams):
    packages: list[v.PackageName] = Field(min_length=1, max_length=50)


class PkgQueryP(StrictParams):
    package: v.PackageName


class UserCreateP(StrictParams):
    username: v.AccountName
    comment: v.FreeLabel = ""
    shell: Literal["/bin/bash", "/bin/sh", "/usr/sbin/nologin", "/bin/zsh"] = "/bin/bash"
    groups: list[v.AccountName] = Field(default_factory=list, max_length=10)
    create_home: bool = True
    system: bool = False


class UserP(StrictParams):
    username: v.AccountName
    remove_home: bool = False


class GroupP(StrictParams):
    group: v.AccountName


class UserGroupP(StrictParams):
    username: v.AccountName
    group: v.AccountName


class PathP(StrictParams):
    path: v.UnixPath


class DirCreateP(StrictParams):
    path: v.UnixPath
    mode: v.Octal = "0755"
    owner: v.AccountName | None = None
    group: v.AccountName | None = None


class ChmodP(StrictParams):
    path: v.UnixPath
    mode: v.Octal
    recursive: bool = False


class ChownP(StrictParams):
    path: v.UnixPath
    owner: v.AccountName
    group: v.AccountName | None = None
    recursive: bool = False


SSH_OPTIONS = {
    "PermitRootLogin": r"^(yes|no|prohibit-password|forced-commands-only)$",
    "PasswordAuthentication": r"^(yes|no)$",
    "PubkeyAuthentication": r"^(yes|no)$",
    "X11Forwarding": r"^(yes|no)$",
    "MaxAuthTries": r"^\d{1,2}$",
    "ClientAliveInterval": r"^\d{1,4}$",
    "ClientAliveCountMax": r"^\d{1,2}$",
    "LoginGraceTime": r"^\d{1,4}$",
    "AllowTcpForwarding": r"^(yes|no|local|remote)$",
}


class SshOptionP(StrictParams):
    option: Literal[tuple(SSH_OPTIONS)]  # type: ignore[valid-type]
    value: str = Field(max_length=20)


class FwPortP(StrictParams):
    port: v.Port
    protocol: Literal["tcp", "udp"] = "tcp"
    source: v.IPv4 | v.Cidr | None = None


class FwRuleP(StrictParams):
    action: Literal["allow", "deny", "reject"] = "allow"
    port: v.Port
    protocol: Literal["tcp", "udp"] = "tcp"
    source: v.IPv4 | v.Cidr | None = Field(None, description="Leave empty for any source")
    comment: v.FreeLabel = Field("", max_length=60)


class FwRuleDelP(StrictParams):
    action: Literal["allow", "deny", "reject"] = "allow"
    port: v.Port
    protocol: Literal["tcp", "udp"] = "tcp"
    source: v.IPv4 | v.Cidr | None = None


_UFW_LINE = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)?\s*(.+?)\s*(?:#\s*(.*))?$")


def parse_ufw_numbered(out: str) -> list[dict]:
    rows = []
    for ln in out.splitlines():
        m = _UFW_LINE.match(ln.strip())
        if not m:
            continue
        to, frm = m.group(2).strip(), m.group(5).strip()
        pm = re.match(r"^(\d+)/(tcp|udp)$", to.replace(" (v6)", ""))
        src = "" if frm.startswith("Anywhere") else frm.replace(" (v6)", "")
        rows.append({"number": int(m.group(1)), "to": to, "action": m.group(3).lower(), "direction": (m.group(4) or "IN").lower(),
                     "from": frm, "comment": (m.group(6) or "").strip(), "port": int(pm.group(1)) if pm else None,
                     "protocol": pm.group(2) if pm else "", "source": src or None, "ipv6": "(v6)" in ln,
                     "manageable": bool(pm) and m.group(3) != "LIMIT"})
    return rows


def parse_firewalld(ports: str, services: str, rich: str) -> list[dict]:
    rows = []
    for item in ports.split():
        if "/" in item and item.split("/")[0].isdigit():
            n, proto = item.split("/", 1)
            rows.append({"kind": "port", "action": "allow", "port": int(n), "protocol": proto, "source": None, "rule": item, "manageable": True})
        else:
            rows.append({"kind": "port", "action": "allow", "port": None, "protocol": "", "source": None, "rule": item, "manageable": False})
    for svc in services.split():
        rows.append({"kind": "service", "action": "allow", "port": None, "protocol": "", "source": None, "rule": svc, "manageable": False})
    for ln in rich.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        src = re.search(r'source address="([^"]+)"', ln)
        prt = re.search(r'port port="(\d+)" protocol="(tcp|udp)"', ln)
        act = "allow" if ln.endswith("accept") else "deny" if ln.endswith("drop") else "reject" if "reject" in ln else "other"
        rows.append({"kind": "rich", "action": act, "port": int(prt.group(1)) if prt else None, "protocol": prt.group(2) if prt else "",
                     "source": src.group(1) if src else None, "rule": ln, "manageable": bool(prt) and act != "other"})
    return rows


class LogsP(StrictParams):
    unit: v.UnitName | None = None
    priority: Literal["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"] = "info"
    since_hours: int = Field(24, ge=1, le=720)
    lines: int = Field(200, ge=1, le=5000)


class ProcP(StrictParams):
    sort_by: Literal["cpu", "mem"] = "cpu"
    limit: int = Field(25, ge=1, le=200)


class RebootP(StrictParams):
    delay_minutes: int = Field(1, ge=0, le=60)
    message: v.FreeLabel = Field("Planned maintenance (InfraPilot)", min_length=3)


class KillP(StrictParams):
    pid: int = Field(ge=2, le=4_194_304)
    signal: Literal["TERM", "KILL", "HUP"] = "TERM"


# Approved commands: fixed argv templates. Only listed placeholders are substituted.
APPROVED_COMMANDS: dict[str, dict] = {
    "disk_usage": {"argv": ["df", "-hP"], "sudo": False, "risk": "read", "desc": "Filesystem usage"},
    "memory": {"argv": ["free", "-m"], "sudo": False, "risk": "read", "desc": "Memory usage"},
    "uptime": {"argv": ["uptime"], "sudo": False, "risk": "read", "desc": "Uptime and load"},
    "listening_ports": {"argv": ["ss", "-tulpn"], "sudo": True, "risk": "read", "desc": "Listening sockets"},
    "failed_units": {"argv": ["systemctl", "--failed", "--no-pager"], "sudo": False, "risk": "read", "desc": "Failed systemd units"},
    "apt_update": {"argv": ["apt-get", "update"], "sudo": True, "risk": "change", "desc": "Refresh APT package index"},
    "pending_updates_apt": {"argv": ["apt", "list", "--upgradable"], "sudo": False, "risk": "read", "desc": "Pending APT upgrades"},
    "pending_updates_dnf": {"argv": ["dnf", "-q", "check-update"], "sudo": False, "risk": "read", "desc": "Pending DNF upgrades"},
    "journal_vacuum": {"argv": ["journalctl", "--vacuum-time=14d"], "sudo": True, "risk": "change", "desc": "Trim journal to 14 days"},
    "reboot_required": {"argv": ["sh", "-c", "test -f /var/run/reboot-required && echo yes || echo no"], "sudo": False, "risk": "read", "desc": "Debian reboot-required flag"},
}


class ApprovedCmdP(StrictParams):
    command: Literal[tuple(APPROVED_COMMANDS)]  # type: ignore[valid-type]


class LinuxDriver(Driver):
    key = "linux"
    category = "linux"
    display_name = "Linux (SSH)"
    vendor = "Linux"
    device_types = ("linux_server",)
    credential_kinds = ("password", "ssh_key")
    default_port = 22

    _client = None
    _pkg_mgr: str | None = None

    # -------------------------------------------------------------- transport
    def _connect(self):
        if self._client is not None:
            return self._client
        import paramiko

        client = paramiko.SSHClient()
        if os.path.exists(KNOWN_HOSTS):
            client.load_host_keys(KNOWN_HOSTS)
        if self.cred.get("host_key_policy", "tofu") == "tofu":
            client.set_missing_host_key_policy(_PinningPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        pkey = None
        if self.cred.get("private_key"):
            pkey = _load_key(self.cred["private_key"], self.cred.get("passphrase"))
        try:
            client.connect(self.device.address, port=self.port or 22, username=self.cred.get("username"),
                           password=self.cred.get("password") if not pkey else None, pkey=pkey,
                           passphrase=self.cred.get("passphrase"), timeout=min(self.timeout, 20),
                           auth_timeout=20, banner_timeout=20, look_for_keys=False, allow_agent=False)
        except Exception as exc:
            raise DeviceConnectionError(f"SSH connection to {self.device.address} failed: {exc}") from exc
        self._client = client
        return client

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    @property
    def _needs_sudo(self) -> bool:
        return self.cred.get("username") != "root" and self.cred.get("become", True)

    def _exec(self, argv: list[str], sudo: bool = False, timeout: int | None = None, stdin: str | None = None) -> CmdResult:
        if sudo and self._needs_sudo:
            argv = ["sudo", "-n", "--"] + argv
        cmd = "LC_ALL=C " + shlex.join(argv)
        client = self._connect()
        chan_in, out, err = client.exec_command(cmd, timeout=timeout or self.timeout)
        if stdin is not None:
            chan_in.write(stdin)
            chan_in.channel.shutdown_write()
        o = out.read().decode("utf-8", "replace")
        e = err.read().decode("utf-8", "replace")
        rc = out.channel.recv_exit_status()
        if rc != 0 and "sudo: a password is required" in e:
            raise Unsupported("This operation needs passwordless sudo (NOPASSWD) for the service account on the target")
        return CmdResult(rc, o, e)

    def _must(self, argv, sudo=False, **kw) -> CmdResult:
        r = self._exec(argv, sudo=sudo, **kw)
        if not r.ok:
            raise RuntimeError(f"Command failed ({r.rc}): {shlex.join(argv)}\n{(r.err or r.out).strip()[:2000]}")
        return r

    def _package_manager(self) -> str:
        if self._pkg_mgr:
            return self._pkg_mgr
        for pm in ("apt-get", "dnf", "yum", "zypper"):
            if self._exec(["sh", "-c", f"command -v {pm}"]).ok:
                self._pkg_mgr = pm
                return pm
        raise Unsupported("No supported package manager (apt-get, dnf, yum, zypper) found on target")

    def _firewall_tool(self) -> str:
        if self._exec(["sh", "-c", "command -v ufw"]).ok:
            return "ufw"
        if self._exec(["sh", "-c", "command -v firewall-cmd"]).ok:
            return "firewalld"
        raise Unsupported("Neither ufw nor firewalld is installed on target")

    # -------------------------------------------------------------- lifecycle
    def test_connection(self) -> ConnectivityResult:
        t0 = time.monotonic()
        facts = self.collect_facts()
        return ConnectivityResult(True, f"SSH OK - {facts.get('os_name', 'Linux')}", (time.monotonic() - t0) * 1000, facts)

    def collect_facts(self) -> dict:
        r = self._must(["sh", "-c", ". /etc/os-release 2>/dev/null; echo \"$PRETTY_NAME|$VERSION_ID\"; hostname; uname -r; "
                        "cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/product_serial 2>/dev/null || true"])
        lines = r.out.splitlines() + [""] * 6
        name, _, ver = lines[0].partition("|")
        return {"os_name": name, "os_version": ver, "hostname": lines[1], "firmware": f"kernel {lines[2]}",
                "vendor": lines[3].strip(), "model": lines[4].strip(), "serial_number": lines[5].strip()}

    def collect_metrics(self) -> dict[str, float]:
        r = self._must(["sh", "-c", "head -1 /proc/stat; sleep 1; head -1 /proc/stat; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo; "
                        "df -P -x tmpfs -x devtmpfs -x squashfs -x overlay | tail -n +2; cat /proc/loadavg; cat /proc/uptime"])
        return parse_linux_metrics(r.out)

    def _ok(self, data, output="", **kw):
        return OpResult(data=data, output=output or (data if isinstance(data, str) else json.dumps(data, indent=2))[:200000], **kw)

    # -------------------------------------------------------------- system
    @operation("linux.system.info", "System information", risk="read")
    def system_info(self, p):
        facts = self.collect_facts()
        r = self._exec(["sh", "-c", "cat /proc/uptime; nproc; grep MemTotal /proc/meminfo; timedatectl show -p Timezone -p NTPSynchronized 2>/dev/null; "
                        "test -f /var/run/reboot-required && echo REBOOT_REQUIRED=yes || echo REBOOT_REQUIRED=no"])
        lines = r.out.splitlines()
        info = {**facts}
        try:
            info["uptime_hours"] = round(float(lines[0].split()[0]) / 3600, 1)
            info["cpus"] = int(lines[1])
            info["memory_gb"] = round(int(lines[2].split()[1]) / 1048576, 1)
        except (IndexError, ValueError):
            pass
        for ln in lines[3:]:
            if "=" in ln:
                k, val = ln.split("=", 1)
                info[k.lower()] = val
        return self._ok(info)

    @operation("linux.system.reboot", "Reboot server", risk="critical", params=RebootP,
               changes="Reboot in {delay_minutes} minute(s) with message '{message}'; services on this host go down")
    def system_reboot(self, p: RebootP):
        self._must(["shutdown", "-r", f"+{p.delay_minutes}" if p.delay_minutes else "now", p.message], sudo=True)
        return OpResult(output=f"Reboot scheduled (+{p.delay_minutes} min)", verification="Use Test connectivity after the reboot to confirm the host is back",
                        rollback="Before it happens: shutdown -c (cancel)")

    @operation("linux.process.kill", "Signal / kill process", risk="change", params=KillP, changes="Send SIG{signal} to process {pid}")
    def process_kill(self, p: KillP):
        before = self._exec(["ps", "-o", "pid=,user=,comm=", "-p", str(p.pid)])
        if not before.ok:
            return OpResult(status="failed", output=f"Process {p.pid} does not exist")
        self._must(["kill", f"-{p.signal}", str(p.pid)], sudo=True)
        time.sleep(1)
        alive = self._exec(["ps", "-p", str(p.pid)]).ok
        ok = (not alive) or p.signal == "HUP"
        return OpResult(status="succeeded" if ok else "failed", output=f"SIG{p.signal} sent to {before.out.strip()}", before=before.out,
                        verification=f"process {'still running' if alive else 'ended'}", rollback="Restart the owning service if needed")

    @operation("linux.updates.pending", "Pending package updates", risk="read")
    def updates_pending(self, p):
        pm = self._package_manager()
        rows = []
        if pm == "apt-get":
            r = self._exec(["apt", "list", "--upgradable"])
            for ln in r.out.splitlines():
                if "/" in ln and "[upgradable from:" in ln:
                    name, rest = ln.split("/", 1)
                    parts = rest.split()
                    rows.append({"package": name, "new_version": parts[1] if len(parts) > 1 else "", "current": ln.split("from:")[-1].strip(" ]"),
                                 "security": "-security" in parts[0]})
        else:
            r = self._exec([pm, "-q", "check-update"])
            for ln in r.out.splitlines():
                f = ln.split()
                if len(f) == 3 and "." in f[0]:
                    rows.append({"package": f[0], "new_version": f[1], "current": "", "security": "security" in f[2]})
        return self._ok(rows, output=f"{len(rows)} pending update(s), {sum(1 for x in rows if x['security'])} security")

    @operation("linux.network.interfaces", "Network interfaces and routes", risk="read")
    def network(self, p):
        addr = self._exec(["ip", "-j", "addr"])
        route = self._exec(["ip", "-j", "route"])
        try:
            rows = [{"interface": i.get("ifname"), "state": i.get("operstate"), "mac": i.get("address"),
                     "addresses": ", ".join(f"{a['local']}/{a['prefixlen']}" for a in i.get("addr_info", []))} for i in json.loads(addr.out)]
            routes = json.loads(route.out) if route.ok else []
        except (json.JSONDecodeError, KeyError):
            rows, routes = [], []
        return self._ok({"interfaces": rows, "routes": routes}, output=json.dumps(rows, indent=1))

    @operation("linux.cron.list", "Scheduled jobs (cron and timers)", risk="read")
    def cron(self, p):
        user_cron = self._exec(["crontab", "-l"])
        system = self._exec(["sh", "-c", "ls -1 /etc/cron.d 2>/dev/null; echo ---; grep -hv '^#' /etc/crontab 2>/dev/null | grep -v '^$'"], sudo=True)
        timers = self._exec(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"])
        rows = [{"next": " ".join(ln.split()[:4]), "unit": ln.split()[-2] if len(ln.split()) > 2 else ln, "activates": ln.split()[-1]}
                for ln in timers.out.splitlines() if ln.strip()]
        return self._ok({"user_crontab": user_cron.out if user_cron.ok else "", "system": system.out, "timers": rows})

    # -------------------------------------------------------------- health
    @operation("linux.health", "System health", risk="read")
    def health(self, p):
        m = self.collect_metrics()
        failed = self._exec(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"]).out.strip().splitlines()
        return self._ok({"metrics": m, "failed_units": [ln.split()[0] for ln in failed if ln.strip()]})

    # -------------------------------------------------------------- systemd
    @operation("linux.services.list", "List systemd services", risk="read")
    def services_list(self, p):
        r = self._must(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"])
        rows = []
        for ln in r.out.splitlines():
            parts = ln.split(None, 4)
            if len(parts) >= 4:
                rows.append({"unit": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3], "description": parts[4] if len(parts) > 4 else ""})
        return self._ok(rows)

    @operation("linux.service.status", "Service status", risk="read", params=UnitP)
    def service_status(self, p: UnitP):
        r = self._exec(["systemctl", "show", p.unit, "--no-pager", "-p", "Id,ActiveState,SubState,UnitFileState,MainPID,ExecMainStartTimestamp,Description"])
        props = dict(ln.split("=", 1) for ln in r.out.splitlines() if "=" in ln)
        if props.get("LoadState") == "not-found" or not props.get("Id"):
            raise RuntimeError(f"Unit {p.unit} not found")
        return self._ok(props)

    def _unit_state(self, unit: str) -> dict:
        r = self._exec(["systemctl", "show", unit, "--no-pager", "-p", "ActiveState,SubState,UnitFileState,LoadState"])
        return dict(ln.split("=", 1) for ln in r.out.splitlines() if "=" in ln)

    def _systemctl(self, p: UnitP, verb: str, expect: dict, check_mode: bool) -> OpResult:
        before = self._unit_state(p.unit)
        if before.get("LoadState") == "not-found":
            return OpResult(status="failed", output=f"Unit {p.unit} not found")
        if check_mode:
            return OpResult(output=f"[check mode] Would run: systemctl {verb} {p.unit} (current: {before})", before=json.dumps(before))
        self._must(["systemctl", verb, p.unit], sudo=True)
        time.sleep(1)
        after = self._unit_state(p.unit)
        ok = all(after.get(k) == val for k, val in expect.items())
        inverse = {"start": "stop", "stop": "start", "enable": "disable", "disable": "enable", "restart": "restart"}[verb]
        return OpResult(status="succeeded" if ok else "failed", output=f"systemctl {verb} {p.unit}: {before.get('ActiveState')} -> {after.get('ActiveState')}",
                        before=json.dumps(before), after=json.dumps(after), verification=f"{after}", rollback=f"systemctl {inverse} {p.unit}")

    @operation("linux.service.start", "Start service", risk="change", params=UnitP, check_mode=True, changes="systemctl start {unit}")
    def svc_start(self, p, check_mode=False):
        return self._systemctl(p, "start", {"ActiveState": "active"}, check_mode)

    @operation("linux.service.stop", "Stop service", risk="change", params=UnitP, check_mode=True, changes="systemctl stop {unit}")
    def svc_stop(self, p, check_mode=False):
        return self._systemctl(p, "stop", {"ActiveState": "inactive"}, check_mode)

    @operation("linux.service.restart", "Restart service", risk="change", params=UnitP, check_mode=True, changes="systemctl restart {unit}")
    def svc_restart(self, p, check_mode=False):
        return self._systemctl(p, "restart", {"ActiveState": "active"}, check_mode)

    @operation("linux.service.enable", "Enable service at boot", risk="change", params=UnitP, check_mode=True, changes="systemctl enable {unit}")
    def svc_enable(self, p, check_mode=False):
        return self._systemctl(p, "enable", {"UnitFileState": "enabled"}, check_mode)

    @operation("linux.service.disable", "Disable service at boot", risk="change", params=UnitP, check_mode=True, changes="systemctl disable {unit}")
    def svc_disable(self, p, check_mode=False):
        return self._systemctl(p, "disable", {"UnitFileState": "disabled"}, check_mode)

    # -------------------------------------------------------------- packages
    @operation("linux.package.query", "Query package", risk="read", params=PkgQueryP)
    def pkg_query(self, p: PkgQueryP):
        pm = self._package_manager()
        if pm == "apt-get":
            r = self._exec(["dpkg-query", "-W", "-f=${Package}|${Version}|${Status}\n", p.package])
        else:
            r = self._exec(["rpm", "-q", "--qf", "%{NAME}|%{VERSION}-%{RELEASE}|installed\n", p.package])
        installed = r.ok and "installed" in r.out
        return self._ok({"package": p.package, "installed": installed, "detail": r.out.strip()})

    def _pkg(self, p: PkgP, action: Literal["install", "remove"], check_mode: bool) -> OpResult:
        pm = self._package_manager()
        argv = {
            ("apt-get", "install"): ["apt-get", "install", "-y", "--no-install-recommends"],
            ("apt-get", "remove"): ["apt-get", "remove", "-y"],
            ("dnf", "install"): ["dnf", "install", "-y"], ("dnf", "remove"): ["dnf", "remove", "-y"],
            ("yum", "install"): ["yum", "install", "-y"], ("yum", "remove"): ["yum", "remove", "-y"],
            ("zypper", "install"): ["zypper", "--non-interactive", "install"], ("zypper", "remove"): ["zypper", "--non-interactive", "remove"],
        }[(pm, action)]
        if check_mode:
            sim = {"apt-get": ["-s"], "dnf": ["--assumeno"], "yum": ["--assumeno"], "zypper": ["--dry-run"]}[pm]
            argv = [a for a in argv if a != "-y"] + sim
        env = ["env", "DEBIAN_FRONTEND=noninteractive"] if pm == "apt-get" else []
        r = self._exec(env + argv + list(p.packages), sudo=True, timeout=max(self.timeout, 900))
        if check_mode:
            # dnf --assumeno exits 1 by design
            return OpResult(status="succeeded", output=f"[check mode]\n{r.out}\n{r.err}"[:200000])
        verified = [self.pkg_query(PkgQueryP(package=x)).data["installed"] for x in p.packages]
        ok = r.ok and all(verified) if action == "install" else r.ok and not any(verified)
        inverse = "remove" if action == "install" else "install"
        return OpResult(status="succeeded" if ok else "failed", output=(r.out + "\n" + r.err)[-200000:],
                        verification=f"installed: {dict(zip(p.packages, verified))}", rollback=f"{pm} {inverse} {' '.join(p.packages)}")

    @operation("linux.package.install", "Install packages", risk="change", params=PkgP, check_mode=True, changes="Install packages: {packages}")
    def pkg_install(self, p, check_mode=False):
        return self._pkg(p, "install", check_mode)

    @operation("linux.package.remove", "Remove packages", risk="critical", params=PkgP, check_mode=True, changes="Remove packages: {packages}")
    def pkg_remove(self, p, check_mode=False):
        return self._pkg(p, "remove", check_mode)

    # -------------------------------------------------------------- users & groups
    @operation("linux.users.list", "List local users", risk="read")
    def users_list(self, p):
        r = self._must(["getent", "passwd"])
        rows = []
        for ln in r.out.splitlines():
            f = ln.split(":")
            if len(f) >= 7:
                rows.append({"username": f[0], "uid": int(f[2]), "gid": int(f[3]), "comment": f[4], "home": f[5], "shell": f[6]})
        return self._ok(rows)

    @operation("linux.user.create", "Create user", risk="change", params=UserCreateP, check_mode=True, changes="Create user '{username}' (groups {groups}, shell {shell})")
    def user_create(self, p: UserCreateP, check_mode=False):
        if self._exec(["id", p.username]).ok:
            return OpResult(status="failed", output=f"User {p.username} already exists")
        argv = ["useradd", "-s", p.shell, "-c", p.comment]
        if p.create_home:
            argv.append("-m")
        if p.system:
            argv.append("-r")
        if p.groups:
            argv += ["-G", ",".join(p.groups)]
        argv.append(p.username)
        if check_mode:
            return OpResult(output="[check mode] Would run: " + shlex.join(argv))
        self._must(argv, sudo=True)
        r = self._exec(["id", p.username])
        return OpResult(status="succeeded" if r.ok else "failed", output=r.out, verification=r.out.strip(), rollback=f"userdel {p.username}")

    @operation("linux.user.delete", "Delete user", risk="critical", params=UserP, changes="Delete user '{username}' (remove home: {remove_home})")
    def user_delete(self, p: UserP):
        before = self._exec(["id", p.username])
        if not before.ok:
            return OpResult(status="failed", output=f"User {p.username} does not exist")
        self._must(["userdel"] + (["-r"] if p.remove_home else []) + [p.username], sudo=True)
        gone = not self._exec(["id", p.username]).ok
        return OpResult(status="succeeded" if gone else "failed", output=f"Deleted {p.username}", before=before.out,
                        rollback="Re-create user manually; " + ("home directory was removed" if p.remove_home else "home directory retained"))

    @operation("linux.group.create", "Create group", risk="change", params=GroupP, changes="Create group '{group}'")
    def group_create(self, p: GroupP):
        self._must(["groupadd", p.group], sudo=True)
        return OpResult(output=f"Group {p.group} created", rollback=f"groupdel {p.group}")

    @operation("linux.user.add_group", "Add user to group", risk="change", params=UserGroupP, changes="Add '{username}' to group '{group}'")
    def user_add_group(self, p: UserGroupP):
        self._must(["usermod", "-aG", p.group, p.username], sudo=True)
        r = self._exec(["id", "-nG", p.username])
        ok = p.group in r.out.split()
        return OpResult(status="succeeded" if ok else "failed", output=r.out, verification=f"groups: {r.out.strip()}", rollback=f"gpasswd -d {p.username} {p.group}")

    # -------------------------------------------------------------- files
    @operation("linux.file.stat", "Inspect file/directory", risk="read", params=PathP)
    def file_stat(self, p: PathP):
        r = self._must(["stat", "-c", "%n|%F|%a|%U|%G|%s|%y", p.path], sudo=True)
        f = r.out.strip().split("|")
        return self._ok({"path": f[0], "type": f[1], "mode": f[2], "owner": f[3], "group": f[4], "size": int(f[5]), "modified": f[6]})

    @operation("linux.dir.create", "Create directory", risk="change", params=DirCreateP, check_mode=True, changes="Create directory {path} mode {mode} owner {owner}:{group}")
    def dir_create(self, p: DirCreateP, check_mode=False):
        exists = self._exec(["test", "-e", p.path]).ok
        if check_mode:
            return OpResult(output=f"[check mode] {'exists already' if exists else 'would create'} {p.path}")
        self._must(["mkdir", "-p", "-m", p.mode, p.path], sudo=True)
        if p.owner:
            self._must(["chown", f"{p.owner}:{p.group}" if p.group else p.owner, p.path], sudo=True)
        st = self.file_stat(PathP(path=p.path)).data
        return OpResult(output=json.dumps(st), verification=f"mode {st['mode']} owner {st['owner']}:{st['group']}",
                        rollback=None if exists else f"rmdir {p.path}")

    @operation("linux.file.chmod", "Change permissions", risk="change", params=ChmodP, changes="chmod {mode} {path} (recursive={recursive})")
    def chmod(self, p: ChmodP):
        before = self.file_stat(PathP(path=p.path)).data
        self._must(["chmod"] + (["-R"] if p.recursive else []) + [p.mode, p.path], sudo=True)
        after = self.file_stat(PathP(path=p.path)).data
        return OpResult(output=f"{before['mode']} -> {after['mode']}", before=json.dumps(before), after=json.dumps(after),
                        rollback=f"chmod {before['mode']} {p.path}")

    @operation("linux.file.chown", "Change ownership", risk="change", params=ChownP, changes="chown {owner}:{group} {path} (recursive={recursive})")
    def chown(self, p: ChownP):
        before = self.file_stat(PathP(path=p.path)).data
        self._must(["chown"] + (["-R"] if p.recursive else []) + [f"{p.owner}:{p.group}" if p.group else p.owner, p.path], sudo=True)
        after = self.file_stat(PathP(path=p.path)).data
        return OpResult(output=f"{before['owner']}:{before['group']} -> {after['owner']}:{after['group']}", before=json.dumps(before),
                        after=json.dumps(after), rollback=f"chown {before['owner']}:{before['group']} {p.path}")

    # -------------------------------------------------------------- SSH config
    @operation("linux.ssh.config", "Effective sshd configuration", risk="read")
    def ssh_config(self, p):
        r = self._must(["sshd", "-T"], sudo=True)
        keys = {k.lower() for k in SSH_OPTIONS} | {"port", "listenaddress", "allowusers", "allowgroups", "ciphers", "macs", "kexalgorithms"}
        return self._ok({ln.split(" ", 1)[0]: ln.split(" ", 1)[1] for ln in r.out.splitlines() if " " in ln and ln.split(" ", 1)[0] in keys})

    @operation("linux.ssh.set_option", "Set sshd option", risk="critical", params=SshOptionP, check_mode=True,
               changes="Set sshd option {option} {value} (config validated with sshd -t before reload; backup kept)")
    def ssh_set(self, p: SshOptionP, check_mode=False):
        import re

        if not re.fullmatch(SSH_OPTIONS[p.option], p.value):
            raise ValueError(f"Invalid value for {p.option}")
        dropin = "/etc/ssh/sshd_config.d/90-infrapilot.conf"
        has_dropin_dir = self._exec(["sh", "-c", "grep -Eiq '^\\s*Include\\s+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config"]).ok
        if not has_dropin_dir:
            raise Unsupported("sshd_config does not include /etc/ssh/sshd_config.d/*.conf; manage this host's sshd_config via a playbook instead")
        current = self._exec(["cat", dropin], sudo=True).out if self._exec(["test", "-f", dropin], sudo=True).ok else ""
        lines = [ln for ln in current.splitlines() if not ln.lower().startswith(p.option.lower() + " ")]
        lines.append(f"{p.option} {p.value}")
        new = "# Managed by InfraPilot\n" + "\n".join(ln for ln in lines if not ln.startswith("# Managed")) + "\n"
        if check_mode:
            return OpResult(output=f"[check mode] {dropin} would become:\n{new}", before=current, after=new)
        stamp = time.strftime("%Y%m%d%H%M%S")
        if current:
            self._must(["cp", "-p", dropin, f"{dropin}.bak-{stamp}"], sudo=True)
        self._must(["tee", dropin], sudo=True, stdin=new)
        test = self._exec(["sshd", "-t"], sudo=True)
        if not test.ok:
            # restore and do not reload
            if current:
                self._must(["cp", "-p", f"{dropin}.bak-{stamp}", dropin], sudo=True)
            else:
                self._must(["rm", "-f", dropin], sudo=True)
            return OpResult(status="failed", output=f"sshd -t rejected the configuration, change reverted:\n{test.err}")
        svc = "ssh" if self._exec(["systemctl", "cat", "ssh.service"]).ok else "sshd"
        self._must(["systemctl", "reload", svc], sudo=True)
        eff = self.ssh_config(None).data
        val = eff.get(p.option.lower())
        return OpResult(status="succeeded" if str(val).lower() == p.value.lower() else "failed", before=current, after=new,
                        output=f"{p.option} now {val}", verification=f"sshd -T reports {p.option.lower()} {val}",
                        rollback=(f"cp {dropin}.bak-{stamp} {dropin} && systemctl reload {svc}" if current else f"rm {dropin} && systemctl reload {svc}"))

    # -------------------------------------------------------------- firewall
    @operation("linux.firewall.status", "Firewall status", risk="read")
    def fw_status(self, p):
        tool = self._firewall_tool()
        r = self._exec(["ufw", "status", "verbose"] if tool == "ufw" else ["firewall-cmd", "--list-all"], sudo=True)
        return self._ok({"tool": tool, "status": r.out}, output=r.out)

    @operation("linux.firewall.allow_port", "Allow port in firewall", risk="change", params=FwPortP, check_mode=True,
               changes="Allow {protocol}/{port} from {source}")
    def fw_allow(self, p: FwPortP, check_mode=False):
        tool = self._firewall_tool()
        if tool == "ufw":
            argv = ["ufw"] + (["--dry-run"] if check_mode else []) + (
                ["allow", "proto", p.protocol, "from", p.source, "to", "any", "port", str(p.port)] if p.source else ["allow", f"{p.port}/{p.protocol}"])
            rb = "ufw delete " + " ".join(argv[1:]) if not check_mode else None
        else:
            if check_mode:
                return OpResult(output=f"[check mode] firewalld would add {p.port}/{p.protocol}" + (f" from {p.source}" if p.source else ""))
            if p.source:
                rule = f'rule family="ipv4" source address="{p.source}" port port="{p.port}" protocol="{p.protocol}" accept'
                argv = ["firewall-cmd", "--permanent", f"--add-rich-rule={rule}"]
                rb = f"firewall-cmd --permanent --remove-rich-rule='{rule}' && firewall-cmd --reload"
            else:
                argv = ["firewall-cmd", "--permanent", f"--add-port={p.port}/{p.protocol}"]
                rb = f"firewall-cmd --permanent --remove-port={p.port}/{p.protocol} && firewall-cmd --reload"
        r = self._must(argv, sudo=True)
        if tool == "firewalld" and not check_mode:
            self._must(["firewall-cmd", "--reload"], sudo=True)
        status = self.fw_status(None).data["status"] if not check_mode else ""
        return OpResult(output=r.out + ("\n" + status if status else ""), after=status or None, rollback=rb,
                        verification=None if check_mode else ("rule visible in status" if str(p.port) in status else "rule NOT visible in status"),
                        status="succeeded" if check_mode or str(p.port) in status else "failed")

    # -------------------------------------------------------------- library scripts
    @operation("linux.script.run", "Run library shell script", risk="change", params=ScriptRunP, check_mode=True,
               changes="Run the reviewed shell script from the library")
    def script_run(self, p: ScriptRunP, check_mode=False):
        require_library_body(p)
        # Values become shell variables assigned with safe quoting; the reviewed body uses "$name".
        assigns = "".join(f"{k}={shlex.quote(str(v).lower() if isinstance(v, bool) else str(v))}\n" for k, v in p.values.items())
        script = f"{assigns}{p.body}\n"
        if check_mode:
            return OpResult(output=f"[check mode] would run '{p.name}'{' with sudo' if p.run_as_root else ''}:\n{script}")
        r = self._exec(["bash", "-s"], sudo=p.run_as_root, stdin=script, timeout=p.timeout_seconds)
        out = (r.out or "") + (("\n--- stderr ---\n" + r.err) if getattr(r, "err", "") else "")
        return OpResult(status="succeeded" if r.ok else "failed", output=out[:200000] or "(no output)",
                        verification=f"exit code {r.rc}", rollback="Use the script's own rollback procedure (documented in its description)")

    # host firewall rule management -------------------------------------------------
    def _fw_rules(self) -> tuple[str, list[dict], str]:
        tool = self._firewall_tool()
        if tool == "ufw":
            st = self._exec(["ufw", "status", "numbered"], sudo=True).out
            return tool, parse_ufw_numbered(st), "active" if "Status: active" in st else "inactive"
        state = self._exec(["firewall-cmd", "--state"], sudo=True).out.strip() or "not running"
        rows = parse_firewalld(self._exec(["firewall-cmd", "--list-ports"], sudo=True).out,
                               self._exec(["firewall-cmd", "--list-services"], sudo=True).out,
                               self._exec(["firewall-cmd", "--list-rich-rules"], sudo=True).out)
        return tool, rows, state

    def _mgmt_port(self) -> int:
        return int(self.port or 22)

    def _firewalld_spec(self, action: str, port: int, proto: str, source: str | None) -> tuple[str, str]:
        if action == "allow" and not source:
            return "port", f"{port}/{proto}"
        verdict = {"allow": "accept", "deny": "drop", "reject": "reject"}[action]
        src = f' source address="{source}"' if source else ""
        return "rich", f'rule family="ipv4"{src} port port="{port}" protocol="{proto}" {verdict}'

    def _ufw_spec(self, action: str, port: int, proto: str, source: str | None) -> list[str]:
        return [action, "proto", proto, "from", source or "any", "to", "any", "port", str(port)]

    @operation("linux.firewall.rules", "Firewall rules", risk="read")
    def fw_rules(self, p):
        tool, rows, state = self._fw_rules()
        return self._ok(rows, output=f"{tool}: {state}, {len(rows)} rule(s)" + ("" if state == "active" or state == "running" else
                                                                                 " - the firewall is not enforcing rules on this host"))

    @operation("linux.firewall.rule.add", "Add firewall rule", risk="change", params=FwRuleP, check_mode=True,
               changes="{action} {protocol}/{port} from {source} on the host firewall")
    def fw_rule_add(self, p: FwRuleP, check_mode=False):
        if p.action != "allow" and p.port == self._mgmt_port() and not p.source:
            raise ValidationFailed(f"Refusing to {p.action} port {p.port} from everywhere: it is the SSH port InfraPilot manages this host through")
        tool, before, state = self._fw_rules()
        if tool == "ufw":
            argv = ["ufw"] + (["--dry-run"] if check_mode else []) + self._ufw_spec(p.action, p.port, p.protocol, p.source) + (["comment", p.comment] if p.comment else [])
            rb = "ufw delete " + " ".join(self._ufw_spec(p.action, p.port, p.protocol, p.source))
            r = self._must(argv, sudo=True)
            out = r.out
        else:
            kind, spec = self._firewalld_spec(p.action, p.port, p.protocol, p.source)
            flag = "--add-port" if kind == "port" else "--add-rich-rule"
            rb = f"firewall-cmd --permanent {flag.replace('add', 'remove')}='{spec}' && firewall-cmd --reload"
            if check_mode:
                return OpResult(output=f"[check mode] firewall-cmd --permanent {flag}='{spec}'", rollback=rb)
            out = self._must(["firewall-cmd", "--permanent", f"{flag}={spec}"], sudo=True).out
            self._must(["firewall-cmd", "--reload"], sudo=True)
        if check_mode:
            return OpResult(output="[check mode]\n" + out, rollback=rb)
        _, after, _ = self._fw_rules()
        hit = any(r_.get("port") == p.port and r_.get("protocol") == p.protocol and r_.get("action") == p.action
                  and (r_.get("source") or None) == (p.source or None) for r_ in after)
        fmt = lambda rows: "\n".join(f"{x.get('action')} {x.get('protocol')}/{x.get('port')} from {x.get('source') or 'any'} {x.get('rule') or x.get('comment') or ''}".strip() for x in rows)  # noqa: E731
        return OpResult(status="succeeded" if hit else "failed", output=out + (f"\nNote: firewall is {state}" if state not in ("active", "running") else ""),
                        before=fmt(before), after=fmt(after), verification=f"rule {'present' if hit else 'NOT found'} after change", rollback=rb)

    @operation("linux.firewall.rule.delete", "Delete firewall rule", risk="change", params=FwRuleDelP, check_mode=True,
               changes="Remove rule {action} {protocol}/{port} from {source} on the host firewall")
    def fw_rule_delete(self, p: FwRuleDelP, check_mode=False):
        if p.action == "allow" and p.port == self._mgmt_port():
            raise ValidationFailed(f"Refusing to remove an allow rule for port {p.port}: it is the SSH port InfraPilot uses for this host")
        tool, before, _ = self._fw_rules()
        if tool == "ufw":
            spec = self._ufw_spec(p.action, p.port, p.protocol, p.source)
            r = self._must(["ufw"] + (["--dry-run"] if check_mode else []) + ["delete"] + spec, sudo=True)
            out, rb = r.out, "ufw " + " ".join(spec)
        else:
            kind, spec = self._firewalld_spec(p.action, p.port, p.protocol, p.source)
            flag = "--remove-port" if kind == "port" else "--remove-rich-rule"
            rb = f"firewall-cmd --permanent {flag.replace('remove', 'add')}='{spec}' && firewall-cmd --reload"
            if check_mode:
                return OpResult(output=f"[check mode] firewall-cmd --permanent {flag}='{spec}'", rollback=rb)
            out = self._must(["firewall-cmd", "--permanent", f"{flag}={spec}"], sudo=True).out
            self._must(["firewall-cmd", "--reload"], sudo=True)
        if check_mode:
            return OpResult(output="[check mode]\n" + out, rollback=rb)
        _, after, _ = self._fw_rules()
        gone = not any(r_.get("port") == p.port and r_.get("protocol") == p.protocol and r_.get("action") == p.action
                       and (r_.get("source") or None) == (p.source or None) for r_ in after)
        return OpResult(status="succeeded" if gone else "failed", output=out, before=str(len(before)) + " rules before",
                        after=str(len(after)) + " rules after", verification=f"rule {'removed' if gone else 'still present'}", rollback=rb)

    # -------------------------------------------------------------- storage / logs / processes
    @operation("linux.storage.list", "Disks, filesystems and mounts", risk="read")
    def storage(self, p):
        lsblk = self._exec(["lsblk", "-J", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL"])
        df = self._must(["df", "-PT", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"])
        fs = []
        for ln in df.out.splitlines()[1:]:
            f = ln.split()
            if len(f) >= 7:
                fs.append({"filesystem": f[0], "type": f[1], "size_kb": int(f[2]), "used_kb": int(f[3]), "avail_kb": int(f[4]), "use_pct": int(f[5].rstrip("%")), "mount": f[6]})
        try:
            blk = json.loads(lsblk.out) if lsblk.ok else {}
        except json.JSONDecodeError:
            blk = {}
        return self._ok({"block_devices": blk.get("blockdevices", []), "filesystems": fs})

    @operation("linux.logs.query", "Query journal logs", risk="read", params=LogsP)
    def logs(self, p: LogsP):
        argv = ["journalctl", "--no-pager", "-o", "short-iso", "-p", p.priority, "--since", f"-{p.since_hours}h", "-n", str(p.lines)]
        if p.unit:
            argv += ["-u", p.unit]
        r = self._exec(argv, sudo=True)
        if not r.ok:
            raise RuntimeError(r.err or "journalctl failed")
        return self._ok(r.out, output=r.out)

    @operation("linux.processes.top", "Top processes", risk="read", params=ProcP)
    def processes(self, p: ProcP):
        r = self._must(["ps", "-eo", "pid,user,pcpu,pmem,rss,etime,comm", f"--sort=-{'pcpu' if p.sort_by == 'cpu' else 'pmem'}"])
        rows = []
        for ln in r.out.splitlines()[1:p.limit + 1]:
            f = ln.split(None, 6)
            if len(f) == 7:
                rows.append({"pid": int(f[0]), "user": f[1], "cpu_pct": float(f[2]), "mem_pct": float(f[3]), "rss_kb": int(f[4]), "elapsed": f[5], "command": f[6]})
        return self._ok(rows)

    @operation("linux.command.approved", "Run approved command", risk="change", params=ApprovedCmdP,
               changes="Run approved maintenance command '{command}'")
    def approved(self, p: ApprovedCmdP):
        spec = APPROVED_COMMANDS[p.command]
        r = self._exec(spec["argv"], sudo=spec["sudo"], timeout=max(self.timeout, 600))
        ok = r.ok or (p.command == "pending_updates_dnf" and r.rc == 100)
        return OpResult(status="succeeded" if ok else "failed", output=(r.out + ("\n" + r.err if r.err else ""))[:200000], data={"rc": r.rc})


def parse_linux_metrics(out: str) -> dict[str, float]:
    lines = out.splitlines()
    m: dict[str, float] = {}
    try:
        a = [int(x) for x in lines[0].split()[1:]]
        b = [int(x) for x in lines[1].split()[1:]]
        idle_a, idle_b = a[3] + (a[4] if len(a) > 4 else 0), b[3] + (b[4] if len(b) > 4 else 0)
        tot = sum(b) - sum(a)
        m["cpu_pct"] = round(100.0 * (1 - (idle_b - idle_a) / tot), 2) if tot > 0 else 0.0
    except (IndexError, ValueError):
        pass
    mem = {}
    disk_max = 0.0
    for ln in lines[2:]:
        if ln.startswith(("MemTotal:", "MemAvailable:")):
            k, val = ln.split(":")
            mem[k] = float(val.split()[0])
        elif ln.startswith("/") or (ln and ln.split()[-1].startswith("/") and "%" in ln):
            f = ln.split()
            if len(f) >= 6 and f[4].endswith("%"):
                disk_max = max(disk_max, float(f[4].rstrip("%")))
    if mem.get("MemTotal"):
        m["mem_pct"] = round(100.0 * (1 - mem.get("MemAvailable", 0) / mem["MemTotal"]), 2)
    m["disk_pct"] = disk_max
    for ln in lines[-2:]:
        f = ln.split()
        if len(f) == 5 and "/" in f[3]:
            m["load1"] = float(f[0])
        elif len(f) == 2:
            try:
                m["uptime_hours"] = round(float(f[0]) / 3600, 2)
            except ValueError:
                pass
    return m


def _load_key(text: str, passphrase: str | None):
    import paramiko

    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase)
        except Exception:
            continue
    raise DeviceConnectionError("Unsupported or invalid SSH private key format")


class _PinningPolicy:
    """Trust-on-first-use: pin the key to known_hosts; later mismatches are rejected by paramiko."""

    def missing_host_key(self, client, hostname, key):
        client.get_host_keys().add(hostname, key.get_name(), key)
        try:
            os.makedirs(os.path.dirname(KNOWN_HOSTS), exist_ok=True)
            client.save_host_keys(KNOWN_HOSTS)
        except OSError:
            pass
