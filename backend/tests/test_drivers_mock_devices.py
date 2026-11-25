"""Mock-device tests for the real drivers: no network access, transports are faked."""
import json
import shlex

import httpx
import pytest

from app.core.errors import Unsupported
from app.drivers.base import DeviceInfo
from app.drivers.firewall import FortiGateDriver, SophosXGSDriver, analyse_rules
from app.drivers.linux import CmdResult, LinuxDriver, parse_linux_metrics
from app.drivers.network import CiscoIOSDriver, MikroTikDriver
from app.drivers.registry import DRIVERS
from app.drivers.virtualization import ProxmoxDriver
from app.drivers.windows import WindowsDriver


def info(platform, **kw):
    return DeviceInfo(id=1, hostname="h", address="192.0.2.10", platform=platform, device_type="x", **kw)


# ---------------------------------------------------------------- Windows
class FakeWin(WindowsDriver):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.calls = []
        self.state = "Stopped"

    def _invoke(self, script, params=None):
        self.calls.append((script, params))
        if "Restart-Service" in script or "Start-Service" in script:
            self.state = "Running"
        if "Get-Service -Name $Name" in script:
            return [{"Name": params["Name"], "Status": self.state, "StartType": "Automatic"}]
        if "Get-Module -ListAvailable -Name ActiveDirectory" in script:
            raise Unsupported("PowerShell module ActiveDirectory is not available on this host")
        return []


def test_windows_params_are_bound_not_interpolated():
    d = FakeWin(info("windows"), {"username": "a", "password": "b"})
    res = d.run("windows.service.restart", {"name": "Spooler"})
    assert res.status == "succeeded" and "Stopped -> Running" in res.output
    for script, params in d.calls:
        assert "Spooler" not in script  # value only travels as a PSRP parameter
        assert script.lstrip().startswith("param(")
    assert res.rollback


def test_windows_rejects_injection_in_params():
    d = FakeWin(info("windows"), {})
    with pytest.raises(Exception):
        d.run("windows.service.restart", {"name": "Spooler'; Stop-Computer"})
    with pytest.raises(Exception):
        d.run("windows.folder.create", {"path": "C:\\data\\x|calc"})


def test_windows_check_mode():
    d = FakeWin(info("windows"), {})
    res = d.run("windows.service.stop", {"name": "Spooler"}, check_mode=True)
    assert "[check mode]" in res.output and not any("Stop-Service" in s for s, _ in d.calls)


def test_windows_missing_module_is_unsupported():
    d = FakeWin(info("windows"), {})
    with pytest.raises(Unsupported):
        d.run("windows.ad.users.list", {})


def test_windows_secret_params_declared():
    assert "password" in WindowsDriver.get_spec("windows.ad.user.create").secret_params


# ---------------------------------------------------------------- Linux
class FakeLinux(LinuxDriver):
    """Simulates a Debian host with systemd and apt."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.cmds = []
        self.units = {"nginx.service": "inactive"}
        self.installed = set()

    def _exec(self, argv, sudo=False, timeout=None, stdin=None):
        if sudo and self._needs_sudo:
            argv = ["sudo", "-n", "--"] + argv
        self.cmds.append(shlex.join(argv))
        a = argv[3:] if argv[:1] == ["sudo"] else argv
        if a[:2] == ["sh", "-c"] and "command -v apt-get" in a[2]:
            return CmdResult(0, "/usr/bin/apt-get", "")
        if a[:2] == ["sh", "-c"] and "command -v" in a[2]:
            return CmdResult(1, "", "")
        if a[:2] == ["systemctl", "show"]:
            u = a[2]
            if u not in self.units:
                return CmdResult(0, "LoadState=not-found\n", "")
            return CmdResult(0, f"ActiveState={self.units[u]}\nSubState=running\nUnitFileState=enabled\nLoadState=loaded\n", "")
        if a[:2] == ["systemctl", "restart"]:
            self.units[a[2]] = "active"
            return CmdResult(0, "", "")
        if a[:1] == ["env"] and "install" in a:
            pk = a[-1]
            if "-s" not in a:
                self.installed.add(pk)
            return CmdResult(0, f"Setting up {pk}", "")
        if a[:1] == ["dpkg-query"]:
            pk = a[-1]
            return (CmdResult(0, f"{pk}|1.0|install ok installed", "") if pk in self.installed else CmdResult(1, "", "no packages"))
        return CmdResult(0, "", "")


def test_linux_restart_with_verification_and_sudo():
    d = FakeLinux(info("linux"), {"username": "ops", "password": "x"})
    res = d.run("linux.service.restart", {"unit": "nginx.service"})
    assert res.status == "succeeded" and "inactive -> active" in res.output
    assert "sudo -n -- systemctl restart nginx.service" in d.cmds


def test_linux_unknown_unit_fails_not_succeeds():
    d = FakeLinux(info("linux"), {"username": "root"})
    assert d.run("linux.service.restart", {"unit": "ghost.service"}).status == "failed"


def test_linux_package_install_and_check_mode():
    d = FakeLinux(info("linux"), {"username": "root"})
    r = d.run("linux.package.install", {"packages": ["htop"]}, check_mode=True)
    assert "[check mode]" in r.output and "htop" not in d.installed
    assert any(" -s htop" in c for c in d.cmds)
    r = d.run("linux.package.install", {"packages": ["htop"]})
    assert r.status == "succeeded" and r.rollback == "apt-get remove htop"


def test_linux_arguments_are_quoted():
    d = FakeLinux(info("linux"), {"username": "root"})
    with pytest.raises(Exception):
        d.run("linux.dir.create", {"path": "/srv/$(reboot)", "mode": "0750"})
    with pytest.raises(Exception):
        d.run("linux.command.approved", {"command": "rm -rf /"})


def test_linux_metrics_parser():
    out = ("cpu  100 0 100 800 0 0 0 0 0 0\ncpu  150 0 150 900 0 0 0 0 0 0\nMemTotal: 1000 kB\nMemAvailable: 250 kB\n"
           "/dev/sda1 100 50 50 50% /\n/dev/sdb1 100 91 9 91% /data\n0.50 0.40 0.30 1/200 1234\n7200.0 14000.0\n")
    m = parse_linux_metrics(out)
    assert m["cpu_pct"] == 50.0 and m["mem_pct"] == 75.0 and m["disk_pct"] == 91.0 and m["load1"] == 0.5 and m["uptime_hours"] == 2.0


# ---------------------------------------------------------------- Network CLI
class FakeConn:
    def __init__(self):
        self.vlans = {1: "default"}
        self.sent = []

    def send_command(self, cmd, **kw):
        if cmd == "show running-config":
            return "hostname sw1\n" + "".join(f"vlan {v}\n name {n}\n" for v, n in sorted(self.vlans.items()))
        if cmd == "show startup-config":
            return "hostname sw1\n"
        if cmd == "show vlan brief":
            return "\n".join(f"{v}    {n}    active" for v, n in sorted(self.vlans.items()))
        if cmd == "show version":
            return "Cisco IOS XE Software, Version 17.9.4\ncisco C9300-48P (X86) processor\nProcessor board ID FOC1234X0YZ\nsw1 uptime is 3 weeks"
        return ""

    def send_config_set(self, lines, **kw):
        self.sent.append(lines)
        if lines[0].startswith("vlan "):
            self.vlans[int(lines[0].split()[1])] = lines[1].split(" ", 1)[1]
        return "config term\n" + "\n".join(lines) + "\nend"

    def send_command_timing(self, cmd, **kw):
        self.sent.append([cmd])
        return "[OK]"

    def disconnect(self):
        pass


def test_cisco_vlan_create_captures_before_after_and_verifies():
    d = CiscoIOSDriver(info("cisco_ios"), {"username": "a", "password": "b"})
    d._conn = FakeConn()
    res = d.run("network.vlan.create", {"vlan_id": 120, "name": "VOICE"})
    assert res.status == "succeeded" and "matched" in res.verification
    kinds = [k for k, _ in res.config_backups]
    assert kinds == ["running-before", "running"] and "vlan 120" in res.config_backups[1][1]
    assert ["write memory"] in d._conn.sent and "no vlan 120" in res.rollback


def test_cisco_facts():
    d = CiscoIOSDriver(info("cisco_ios"), {})
    d._conn = FakeConn()
    f = d.collect_facts()
    assert f["firmware"] == "17.9.4" and f["serial_number"] == "FOC1234X0YZ" and f["os_name"] == "Cisco IOS-XE"


def test_cisco_check_mode_sends_nothing():
    d = CiscoIOSDriver(info("cisco_ios"), {})
    d._conn = FakeConn()
    res = d.run("network.port.access", {"interface": "GigabitEthernet1/0/5", "vlan_id": 20}, check_mode=True)
    assert "switchport access vlan 20" in res.output and d._conn.sent == []


def test_vlan_bounds_and_interface_injection():
    with pytest.raises(Exception):
        CiscoIOSDriver.validate_params("network.vlan.create", {"vlan_id": 5000, "name": "x"})
    with pytest.raises(Exception):
        CiscoIOSDriver.validate_params("network.port.access", {"interface": "Gi1/0/1\nreload", "vlan_id": 10})


def test_mikrotik_vlan_ops_not_claimed():
    assert "network.vlan.create" not in MikroTikDriver.operations
    with pytest.raises(Unsupported):
        MikroTikDriver.get_spec("network.port.trunk")


def test_every_driver_declares_valid_operations():
    for key, cls in DRIVERS.items():
        for op_id, spec in cls.operations.items():
            assert spec.risk in ("read", "change", "critical"), (key, op_id)
            spec.params.model_json_schema()
            if spec.risk != "read":
                assert spec.changes or spec.description, (key, op_id)


# ---------------------------------------------------------------- FortiGate
def forti_transport():
    policies = {7: {"policyid": 7, "name": "allow-all", "status": "enable", "action": "accept", "srcintf": [{"name": "wan1"}],
                    "dstintf": [{"name": "lan"}], "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "ALL"}], "logtraffic": "disable"},
                8: {"policyid": 8, "name": "web", "status": "enable", "action": "accept", "srcintf": [{"name": "lan"}],
                    "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": "lan-net"}], "dstaddr": [{"name": "all"}],
                    "service": [{"name": "HTTPS"}], "logtraffic": "all"}}

    def handler(req: httpx.Request):
        assert req.headers["authorization"] == "Bearer tok"
        p = req.url.path
        if p == "/api/v2/monitor/system/status":
            return httpx.Response(200, json={"version": "v7.4.3", "build": 2573, "serial": "FGT60F123", "results": {"model_name": "FortiGate-60F", "hostname": "fw1"}})
        if p == "/api/v2/monitor/system/config/backup":
            st = ",".join(f"{k}:{v['status']}" for k, v in sorted(policies.items()))
            return httpx.Response(200, text=f"#config-version=FGT60F-7.4.3\nconfig firewall policy\n# {st}\nend\n")
        if p == "/api/v2/cmdb/firewall/policy" and req.method == "GET":
            return httpx.Response(200, json={"results": list(policies.values())})
        if p.startswith("/api/v2/cmdb/firewall/policy/"):
            pid = int(p.rsplit("/", 1)[1])
            if req.method == "PUT":
                policies[pid].update(json.loads(req.content))
                return httpx.Response(200, json={"status": "success"})
            return httpx.Response(200, json={"results": [policies[pid]]})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def forti():
    d = FortiGateDriver(info("fortigate"), {"token": "tok"})
    d._client = httpx.Client(base_url="https://fw", transport=forti_transport(), headers={"Authorization": "Bearer tok"})
    return d


def test_fortigate_facts_and_analysis():
    d = forti()
    assert d.collect_facts()["serial_number"] == "FGT60F123"
    res = d.run("firewall.rules.analyse", {})
    f = res.data["findings"]
    assert f[0]["rule_id"] == 7 and f[0]["severity"] == "critical" and set(f[0]["issues"]) == {"source=ANY", "destination=ANY", "service=ANY"}
    assert any(x["rule_id"] == 8 and x["severity"] == "medium" for x in f)


def test_fortigate_policy_toggle_with_backup_diff_and_verification():
    d = forti()
    res = d.run("firewall.rule.set_enabled", {"policy_id": 7, "enabled": False})
    assert res.status == "succeeded" and "status = disable" in res.verification
    assert [k for k, _ in res.config_backups] == ["full-before", "full"]
    assert "7:enable" in res.before and "7:disable" in res.after
    assert "enable" in res.rollback


def test_fortigate_unknown_endpoint_is_unsupported():
    d = forti()
    with pytest.raises(Unsupported):
        d.run("firewall.vpn.status", {})


# ---------------------------------------------------------------- Sophos
def test_sophos_rules_and_no_log_capability():
    xml = """<Response><Login><status>Authentication Successful</status></Login>
<FirewallRule><Name>Any-Any</Name><Status>Enable</Status><Position>1</Position><NetworkPolicy><Action>Accept</Action>
<SourceZones><Zone>WAN</Zone></SourceZones><LogTraffic>Disable</LogTraffic></NetworkPolicy></FirewallRule></Response>"""

    def handler(req):
        assert b"reqxml" in req.content
        return httpx.Response(200, text=xml)
    d = SophosXGSDriver(info("sophos_xgs"), {"username": "api", "password": "p<&>"})
    d._client = httpx.Client(base_url="https://fw", transport=httpx.MockTransport(handler))
    assert "p&lt;&amp;&gt;" in d._login_xml()
    res = d.run("firewall.rules.analyse", {})
    assert res.data["findings"][0]["severity"] == "critical"
    assert "firewall.logs" not in SophosXGSDriver.operations


def test_sophos_login_failure():
    def handler(req):
        return httpx.Response(200, text="<Response><Login><status>Authentication Failure</status></Login></Response>")
    d = SophosXGSDriver(info("sophos_xgs"), {"username": "api", "password": "x"})
    d._client = httpx.Client(base_url="https://fw", transport=httpx.MockTransport(handler))
    from app.core.errors import DeviceConnectionError
    with pytest.raises(DeviceConnectionError):
        d.test_connection()


# ---------------------------------------------------------------- Proxmox
def test_proxmox_vms_and_metrics():
    def handler(req):
        p = req.url.path
        if p.endswith("/nodes"):
            return httpx.Response(200, json={"data": [{"node": "pve1", "status": "online", "cpu": 0.25, "mem": 50, "maxmem": 100, "disk": 10, "maxdisk": 100, "uptime": 3600}]})
        if p.endswith("/cluster/resources"):
            return httpx.Response(200, json={"data": [{"vmid": 101, "name": "db", "type": "qemu", "node": "pve1", "status": "running", "cpu": 0.1, "mem": 1, "maxmem": 4}]})
        return httpx.Response(404)
    d = ProxmoxDriver(info("proxmox"), {"username": "root@pam!ip", "token": "uuid"})
    d._client = httpx.Client(base_url="https://pve/api2/json", transport=httpx.MockTransport(handler))
    assert d.collect_metrics() == {"cpu_pct": 25.0, "mem_pct": 50.0, "disk_pct": 10.0}
    assert d.run("virt.vms", {}).data[0]["mem_pct"] == 25.0


def test_rule_analysis_ignores_disabled_and_deny():
    rules = [{"id": 1, "action": "deny", "src": ["all"], "dst": ["all"], "service": ["ALL"]},
             {"id": 2, "action": "accept", "enabled": False, "src": ["all"], "dst": ["all"], "service": ["ALL"]}]
    assert analyse_rules(rules) == []


# ---------------------------------------------------------------- Ansible runner (real ansible, local connection)
def test_playbook_runner_end_to_end_local(admin_db_device_factory=None):
    import shutil
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible not installed")
    import os
    import tempfile
    from app.automation import runner
    from app.core.config import get_settings
    from app.core.db import SessionLocal
    from app.models import Device, Job, JobExecution
    s = get_settings()
    s.ansible_work_dir = tempfile.mkdtemp()
    s.playbook_dir = tempfile.mkdtemp()
    # stand-in playbook under a catalogue name: exercises runner isolation/stats/check-mode, not the host's package manager
    with open(os.path.join(s.playbook_dir, "linux_packages.yml"), "w") as fh:
        fh.write("- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.debug: {msg: 'pkgs {{ packages }}'}\n"
                 "    - ansible.builtin.fail: {msg: boom}\n      when: packages[0] == 'fail-me'\n")
    db = SessionLocal()
    d = Device(hostname="localhost", ip_address="127.0.0.1", device_type="linux_server", platform="linux", environment="test")
    db.add(d)
    db.flush()
    job = Job(title="t", kind="playbook", playbook="linux_packages.yml", category="linux", params={"packages": ["bash"], "state": "present"},
              check_mode=True, status="running", worker_id="t")
    db.add(job)
    db.flush()
    db.add(JobExecution(job_id=job.id, device_id=d.id))
    db.commit()
    orig = runner._host_vars
    runner._host_vars = lambda db_, dev, kd: {"ansible_connection": "local", "ansible_python_interpreter": __import__("sys").executable}
    try:
        runner.run_playbook_job(db, job)
    finally:
        runner._host_vars = orig
    db.refresh(job)
    ex = job.executions[0]
    assert ex.status == "succeeded", ex.output
    assert "check mode" in ex.verification
    assert "pkgs ['bash']" in ex.output
    assert os.listdir(s.ansible_work_dir) == []  # isolation dir removed
    job2 = Job(title="t2", kind="playbook", playbook="linux_packages.yml", category="linux", params={"packages": ["fail-me"], "state": "present"},
               status="running", worker_id="t")
    db.add(job2)
    db.flush()
    db.add(JobExecution(job_id=job2.id, device_id=d.id))
    db.commit()
    runner._host_vars = lambda db_, dev, kd: {"ansible_connection": "local", "ansible_python_interpreter": __import__("sys").executable}
    try:
        runner.run_playbook_job(db, job2)
    finally:
        runner._host_vars = orig
    db.refresh(job2)
    assert job2.executions[0].status == "failed"
    db.close()
