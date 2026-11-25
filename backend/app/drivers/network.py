"""Network device drivers (SSH CLI via Netmiko) - one driver class per vendor family.

Each vendor declares its own command set; operations a vendor CLI cannot perform
safely are not declared, so they surface as "unsupported" instead of guessed commands.
Every configuration change captures running-config before and after; the worker
stores both as backups plus a unified diff, and the result carries rollback lines.
"""
from __future__ import annotations

import re
import time
from typing import ClassVar

from pydantic import Field

from app.core.errors import DeviceConnectionError, Unsupported
from app.drivers import validators as v
from app.drivers.base import ScriptRunP, render_cli, require_library_body, ConnectivityResult, Driver, OpResult, StrictParams, operation


class VlanCreateP(StrictParams):
    vlan_id: v.VlanId
    name: v.ObjectName


class VlanDeleteP(StrictParams):
    vlan_id: v.VlanId


class AccessPortP(StrictParams):
    interface: v.InterfaceName
    vlan_id: v.VlanId
    description: v.FreeLabel = ""


class TrunkPortP(StrictParams):
    interface: v.InterfaceName
    allowed_vlans: v.VlanList
    native_vlan: v.VlanId | None = None


class IfAdminP(StrictParams):
    interface: v.InterfaceName
    enabled: bool


class IfDescP(StrictParams):
    interface: v.InterfaceName
    description: v.FreeLabel


class StaticRouteP(StrictParams):
    destination: v.Cidr
    next_hop: v.IPv4
    remove: bool = False


class ShowP(StrictParams):
    command: str = Field(description="Pre-approved show command key")


def cidr_to_mask(cidr: str) -> tuple[str, str]:
    import ipaddress

    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.netmask)


class NetworkDriver(Driver):
    category = "network"
    device_types = ("switch", "router", "access_point")
    credential_kinds = ("password", "ssh_key")
    default_port = 22
    netmiko_type: ClassVar[str] = ""
    cmd_running: ClassVar[str | None] = "show running-config"
    cmd_startup: ClassVar[str | None] = "show startup-config"
    cmd_version: ClassVar[str] = "show version"
    cmd_interfaces: ClassVar[str | None] = None
    cmd_vlans: ClassVar[str | None] = None
    cmd_routes: ClassVar[str | None] = None
    cmd_save: ClassVar[str | None] = None
    prompt_hint: ClassVar[str] = "# "
    cmd_logs: ClassVar[str | None] = None
    cmd_neighbors: ClassVar[str | None] = None
    cmd_arp: ClassVar[str | None] = None
    cmd_mac: ClassVar[str | None] = None
    # Operations are only advertised when the platform has the command behind them, so the
    # catalogue never offers something the vendor CLI cannot do.
    op_requires: ClassVar[dict[str, str]] = {
        "network.interfaces": "cmd_interfaces", "network.vlans": "cmd_vlans", "network.routes": "cmd_routes",
        "network.config.save": "cmd_save", "network.logs": "cmd_logs", "network.neighbors": "cmd_neighbors",
        "network.arp": "cmd_arp", "network.mac_table": "cmd_mac",
    }
    show_commands: ClassVar[dict[str, str]] = {}
    supports_check_mode: ClassVar[bool] = True

    _conn = None

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        cls.operations = {k: v for k, v in cls.operations.items() if not (k in cls.op_requires and not getattr(cls, cls.op_requires[k], None))}

    def _connect(self):
        if self._conn is not None:
            return self._conn
        from netmiko import ConnectHandler

        params = dict(device_type=self.netmiko_type, host=self.device.address, port=self.port or 22,
                      username=self.cred.get("username"), password=self.cred.get("password"),
                      secret=self.cred.get("enable_secret") or "", timeout=self.timeout, conn_timeout=20,
                      auth_timeout=20, banner_timeout=20, fast_cli=False)
        if self.cred.get("private_key"):
            import os, tempfile
            fd, path = tempfile.mkstemp(prefix="ipk_")
            with os.fdopen(fd, "w") as fh:
                fh.write(self.cred["private_key"])
            os.chmod(path, 0o600)
            params.update(use_keys=True, key_file=path)
            self._keyfile = path
        try:
            self._conn = ConnectHandler(**params)
            if self.cred.get("enable_secret"):
                self._conn.enable()
        except Exception as exc:
            raise DeviceConnectionError(f"SSH CLI connection to {self.device.address} failed: {exc}") from exc
        finally:
            kf = getattr(self, "_keyfile", None)
            if kf:
                import os
                try:
                    os.remove(kf)
                except OSError:
                    pass
        return self._conn

    def close(self):
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    def _show(self, cmd: str) -> str:
        out = self._connect().send_command(cmd, read_timeout=self.timeout)
        if re.search(r"^\s*(%\s*Invalid|% Unknown command|Invalid input|bad command name|Error:)", out, re.M):
            raise Unsupported(f"Device rejected command '{cmd}': {out.strip()[:200]}")
        return out

    def _config(self, lines: list[str]) -> str:
        out = self._connect().send_config_set(lines, read_timeout=self.timeout, cmd_verify=True)
        if re.search(r"(% ?Invalid|Invalid input|% Incomplete|Error:|failure:|bad command)", out, re.I):
            raise RuntimeError(f"Device rejected configuration:\n{out[-2000:]}")
        return out

    def _save(self) -> str:
        if not self.cmd_save:
            return ""
        return self._connect().send_command_timing(self.cmd_save, read_timeout=120)

    # -------------------------------------------------------------- lifecycle
    def test_connection(self) -> ConnectivityResult:
        t0 = time.monotonic()
        out = self._show(self.cmd_version)
        facts = self.parse_facts(out)
        return ConnectivityResult(True, f"SSH CLI OK ({self.display_name})", (time.monotonic() - t0) * 1000, facts)

    def collect_facts(self) -> dict:
        return self.parse_facts(self._show(self.cmd_version))

    def parse_facts(self, out: str) -> dict:
        return {"vendor": self.vendor}

    def collect_metrics(self) -> dict[str, float]:
        # Network health metrics are collected via SNMPv3 (see snmp module) when an SNMP credential is set.
        return {}

    # -------------------------------------------------------------- change wrapper
    def _change(self, lines: list[str], rollback_lines: list[str], verify_cmd: str | None, verify_pattern: str | None,
                check_mode: bool, save: bool = True) -> OpResult:
        if check_mode:
            return OpResult(output="[check mode] Configuration that would be applied:\n" + "\n".join(lines),
                            rollback="\n".join(rollback_lines))
        before = self._show(self.cmd_running) if self.cmd_running else None
        out = self._config(lines)
        save_out = self._save() if save else ""
        after = self._show(self.cmd_running) if self.cmd_running else None
        verification, status = None, "succeeded"
        if verify_cmd:
            vout = self._show(verify_cmd)
            hit = bool(re.search(verify_pattern, vout, re.M | re.I)) if verify_pattern else True
            verification = f"{verify_cmd}: {'matched' if hit else 'NOT matched'} /{verify_pattern}/\n{vout[:3000]}"
            status = "succeeded" if hit else "failed"
        backups = []
        if before is not None:
            backups = [("running-before", before), ("running", after or "")]
        return OpResult(status=status, output=out + ("\n" + save_out if save_out else ""), before=before, after=after,
                        verification=verification, rollback="Apply in config mode:\n" + "\n".join(rollback_lines),
                        config_backups=backups)

    # -------------------------------------------------------------- library scripts
    @operation("network.script.run", "Run library CLI script", risk="change", params=ScriptRunP, check_mode=True,
               changes="Run the reviewed CLI script from the library")
    def script_run(self, p: ScriptRunP, check_mode=False):
        require_library_body(p)
        lines = render_cli(p.body, p.values)
        if p.mode == "read":
            if check_mode:
                return OpResult(output="[check mode] commands that would run:\n" + "\n".join(lines))
            out = "\n".join(f"{self.prompt_hint}{c}\n{self._show(c)}" for c in lines)
            return OpResult(output=out[:200000])
        if check_mode:
            return OpResult(output="[check mode] configuration that would be applied:\n" + "\n".join(lines)
                            + ("\n(then: save running configuration)" if p.save_config and self.cmd_save else ""))
        before = self._show(self.cmd_running) if self.cmd_running else None
        status, out, err = "succeeded", "", None
        try:
            out = self._config(lines)
            if p.save_config and self.cmd_save:
                out += "\n" + self._save()
        except Exception as exc:  # keep before/after so a partly applied script can be reviewed and reverted
            status, err = "failed", str(exc)
        after = self._show(self.cmd_running) if self.cmd_running else None
        backups = [("running-before", before), ("running", after or "")] if before is not None else []
        return OpResult(status=status, output=((err + "\n\n") if err else "") + out, before=before, after=after,
                        verification=("device accepted all lines" if status == "succeeded" else "device REJECTED a line - check what was applied")
                        + ("; configuration saved" if status == "succeeded" and p.save_config and self.cmd_save else ""),
                        rollback="Compare 'running-before' with the new configuration in Config backups and re-apply the previous lines",
                        config_backups=backups)

    # -------------------------------------------------------------- read ops (generic)
    @operation("network.facts", "Device facts", risk="read")
    def facts(self, p):
        return OpResult(data=self.collect_facts(), output=self._show(self.cmd_version))

    @operation("network.config.backup", "Back up configuration", risk="read",
               description="Download running (and startup, if supported) configuration and store it as a versioned backup")
    def backup(self, p):
        backups = []
        if self.cmd_running:
            backups.append(("running", self._show(self.cmd_running)))
        if self.cmd_startup:
            try:
                backups.append(("startup", self._show(self.cmd_startup)))
            except Unsupported:
                pass
        if not backups:
            raise Unsupported("Configuration export is not supported for this platform")
        return OpResult(output="Captured: " + ", ".join(f"{k} ({len(c)} bytes)" for k, c in backups), config_backups=backups)

    def _require(self, attr: str, what: str) -> str:
        cmd = getattr(self, attr)
        if not cmd:
            raise Unsupported(f"{what} is not supported by the {self.display_name} driver")
        return cmd

    @operation("network.interfaces", "Interfaces and port status", risk="read")
    def interfaces(self, p):
        out = self._show(self._require("cmd_interfaces", "Interface listing"))
        return OpResult(output=out, data=self.parse_interfaces(out))

    def parse_interfaces(self, out: str) -> list[dict]:
        return []

    @operation("network.vlans", "VLANs", risk="read")
    def vlans(self, p):
        out = self._show(self._require("cmd_vlans", "VLAN listing"))
        return OpResult(output=out)

    @operation("network.routes", "Routing table", risk="read")
    def routes(self, p):
        out = self._show(self._require("cmd_routes", "Routing table"))
        return OpResult(output=out)

    @operation("network.logs", "Device log", risk="read")
    def logs(self, p):
        out = self._show(self._require("cmd_logs", "Log viewing"))
        return OpResult(output=out[-20000:])

    @operation("network.neighbors", "Neighbours (LLDP/CDP)", risk="read")
    def neighbors(self, p):
        return OpResult(output=self._show(self._require("cmd_neighbors", "Neighbour discovery")))

    @operation("network.arp", "ARP table", risk="read")
    def arp(self, p):
        return OpResult(output=self._show(self._require("cmd_arp", "ARP table")))

    @operation("network.mac_table", "MAC address table", risk="read")
    def mac_table(self, p):
        return OpResult(output=self._show(self._require("cmd_mac", "MAC address table")))

    @operation("network.config.save", "Save running configuration", risk="change",
               changes="Write the running configuration to startup (persists across reboot)")
    def config_save(self, p):
        before = None
        if self.cmd_startup:
            try:
                before = self._show(self.cmd_startup)
            except Unsupported:
                before = None
        out = self._save()
        backups = [("startup-before", before)] if before else []
        return OpResult(output=out or "Saved", before=before, verification="Save command completed without error",
                        rollback="Previous startup configuration is stored as a backup (startup-before)", config_backups=backups)


# ====================================================================== Cisco IOS / IOS-XE
class CiscoIOSDriver(NetworkDriver):
    key = "cisco_ios"
    display_name = "Cisco IOS / IOS-XE"
    vendor = "Cisco"
    netmiko_type = "cisco_ios"
    cmd_interfaces = "show interfaces status"
    cmd_vlans = "show vlan brief"
    cmd_routes = "show ip route"
    cmd_save = "write memory"
    cmd_logs = "show logging"
    cmd_neighbors = "show cdp neighbors"
    cmd_arp = "show ip arp"
    cmd_mac = "show mac address-table"

    def parse_facts(self, out: str) -> dict:
        f = {"vendor": "Cisco"}
        if m := re.search(r"Cisco IOS.*?Version ([^\s,]+)", out):
            f["firmware"] = m.group(1)
            f["os_name"] = "Cisco IOS-XE" if "IOS-XE" in out or "IOS XE" in out else "Cisco IOS"
            f["os_version"] = m.group(1)
        if m := re.search(r"[Pp]rocessor board ID (\S+)", out):
            f["serial_number"] = m.group(1)
        if m := re.search(r"^cisco (\S+)", out, re.M | re.I):
            f["model"] = m.group(1)
        if m := re.search(r"^(\S+) uptime is", out, re.M):
            f["hostname"] = m.group(1)
        return f

    def parse_interfaces(self, out: str) -> list[dict]:
        rows = []
        for ln in out.splitlines():
            m = re.match(r"^(\S+)\s+(.*?)\s+(connected|notconnect|disabled|err-disabled|monitoring|inactive|sfpAbsent)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$", ln)
            if m:
                rows.append({"name": m.group(1), "description": m.group(2).strip(), "status": m.group(3), "vlan": m.group(4),
                             "duplex": m.group(5), "speed": m.group(6), "type": m.group(7).strip()})
        return rows

    @operation("network.vlan.create", "Create VLAN", risk="change", params=VlanCreateP, check_mode=True, changes="Create VLAN {vlan_id} named '{name}'")
    def vlan_create(self, p: VlanCreateP, check_mode=False):
        return self._change([f"vlan {p.vlan_id}", f"name {p.name}"], [f"no vlan {p.vlan_id}"], "show vlan brief", rf"^{p.vlan_id}\s+{re.escape(p.name)}", check_mode)

    @operation("network.vlan.delete", "Delete VLAN", risk="critical", params=VlanDeleteP, check_mode=True, changes="Delete VLAN {vlan_id} (ports in it become inactive)")
    def vlan_delete(self, p: VlanDeleteP, check_mode=False):
        r = self._change([f"no vlan {p.vlan_id}"], [f"vlan {p.vlan_id}"], None, None, check_mode)
        if not check_mode and re.search(rf"^{p.vlan_id}\s", self._show("show vlan brief"), re.M):
            r.status, r.verification = "failed", f"VLAN {p.vlan_id} still present"
        return r

    @operation("network.port.access", "Configure access port", risk="change", params=AccessPortP, check_mode=True,
               changes="Set {interface} as access port in VLAN {vlan_id}")
    def port_access(self, p: AccessPortP, check_mode=False):
        lines = [f"interface {p.interface}", "switchport mode access", f"switchport access vlan {p.vlan_id}"]
        if p.description:
            lines.append(f"description {p.description}")
        return self._change(lines, [f"interface {p.interface}", "! restore previous switchport settings from the 'running-before' backup"],
                            f"show interfaces {p.interface} switchport", rf"Access Mode VLAN: {p.vlan_id}\b", check_mode)

    @operation("network.port.trunk", "Configure trunk port", risk="change", params=TrunkPortP, check_mode=True,
               changes="Set {interface} as trunk allowing VLANs {allowed_vlans} (native {native_vlan})")
    def port_trunk(self, p: TrunkPortP, check_mode=False):
        lines = [f"interface {p.interface}", "switchport mode trunk", f"switchport trunk allowed vlan {p.allowed_vlans}"]
        if p.native_vlan:
            lines.append(f"switchport trunk native vlan {p.native_vlan}")
        return self._change(lines, [f"interface {p.interface}", "! restore previous switchport settings from the 'running-before' backup"],
                            f"show interfaces {p.interface} switchport", r"Operational Mode: trunk|Administrative Mode: trunk", check_mode)

    @operation("network.interface.admin", "Enable/disable interface", risk="change", params=IfAdminP, check_mode=True,
               changes="Set interface {interface} enabled={enabled}")
    def if_admin(self, p: IfAdminP, check_mode=False):
        cmd = "no shutdown" if p.enabled else "shutdown"
        inv = "shutdown" if p.enabled else "no shutdown"
        return self._change([f"interface {p.interface}", cmd], [f"interface {p.interface}", inv], None, None, check_mode)

    @operation("network.interface.description", "Set interface description", risk="change", params=IfDescP, check_mode=True,
               changes="Set description of {interface} to '{description}'")
    def if_desc(self, p: IfDescP, check_mode=False):
        return self._change([f"interface {p.interface}", f"description {p.description}"], [f"interface {p.interface}", "no description"], None, None, check_mode)

    @operation("network.route.static", "Add/remove static route", risk="critical", params=StaticRouteP, check_mode=True,
               changes="Static route {destination} via {next_hop} (remove={remove})")
    def static_route(self, p: StaticRouteP, check_mode=False):
        net, mask = cidr_to_mask(p.destination)
        line = f"ip route {net} {mask} {p.next_hop}"
        return self._change([("no " if p.remove else "") + line], [line if p.remove else "no " + line], "show ip route static", None, check_mode)


# ====================================================================== Aruba AOS-CX
class ArubaCXDriver(NetworkDriver):
    key = "aruba_aoscx"
    display_name = "Aruba AOS-CX"
    vendor = "Aruba (HPE)"
    netmiko_type = "aruba_aoscx"
    cmd_interfaces = "show interface brief"
    cmd_vlans = "show vlan"
    cmd_routes = "show ip route"
    cmd_save = "write memory"
    cmd_logs = "show logging"
    cmd_neighbors = "show lldp neighbor-info"
    cmd_arp = "show arp"
    cmd_mac = "show mac-address-table"

    def parse_facts(self, out: str) -> dict:
        f = {"vendor": "Aruba", "os_name": "AOS-CX"}
        if m := re.search(r"Version\s*:\s*(\S+)", out):
            f["firmware"] = f["os_version"] = m.group(1)
        return f

    @operation("network.vlan.create", "Create VLAN", risk="change", params=VlanCreateP, check_mode=True, changes="Create VLAN {vlan_id} named '{name}'")
    def vlan_create(self, p, check_mode=False):
        return self._change([f"vlan {p.vlan_id}", f"name {p.name}"], [f"no vlan {p.vlan_id}"], "show vlan", rf"^\s*{p.vlan_id}\s+{re.escape(p.name)}", check_mode)

    @operation("network.port.access", "Configure access port", risk="change", params=AccessPortP, check_mode=True, changes="Set {interface} as access port in VLAN {vlan_id}")
    def port_access(self, p, check_mode=False):
        lines = [f"interface {p.interface}", "no routing", f"vlan access {p.vlan_id}"] + ([f"description {p.description}"] if p.description else [])
        return self._change(lines, [f"interface {p.interface}", "! restore from 'running-before' backup"], f"show running-config interface {p.interface}", rf"vlan access {p.vlan_id}\b", check_mode)

    @operation("network.port.trunk", "Configure trunk port", risk="change", params=TrunkPortP, check_mode=True, changes="Set {interface} as trunk allowing VLANs {allowed_vlans}")
    def port_trunk(self, p, check_mode=False):
        lines = [f"interface {p.interface}", "no routing", f"vlan trunk allowed {p.allowed_vlans}"] + ([f"vlan trunk native {p.native_vlan}"] if p.native_vlan else [])
        return self._change(lines, [f"interface {p.interface}", "! restore from 'running-before' backup"], f"show running-config interface {p.interface}", r"vlan trunk allowed", check_mode)

    @operation("network.interface.admin", "Enable/disable interface", risk="change", params=IfAdminP, check_mode=True, changes="Set interface {interface} enabled={enabled}")
    def if_admin(self, p, check_mode=False):
        return self._change([f"interface {p.interface}", "no shutdown" if p.enabled else "shutdown"], [f"interface {p.interface}", "shutdown" if p.enabled else "no shutdown"], None, None, check_mode)


# ====================================================================== HP / HPE ProCurve (ArubaOS-Switch)
class HPProCurveDriver(NetworkDriver):
    key = "hp_procurve"
    display_name = "HPE ProCurve / ArubaOS-Switch"
    vendor = "HPE"
    netmiko_type = "hp_procurve"
    cmd_interfaces = "show interfaces brief"
    cmd_vlans = "show vlans"
    cmd_routes = "show ip route"
    cmd_save = "write memory"
    cmd_logs = "show logging -r"
    cmd_neighbors = "show lldp info remote-device"
    cmd_arp = "show arp"
    cmd_mac = "show mac-address"
    cmd_version = "show system"

    def parse_facts(self, out: str) -> dict:
        f = {"vendor": "HPE", "os_name": "ArubaOS-Switch"}
        if m := re.search(r"Software revision\s*:\s*(\S+)", out):
            f["firmware"] = f["os_version"] = m.group(1)
        if m := re.search(r"Serial Number\s*:\s*(\S+)", out):
            f["serial_number"] = m.group(1)
        return f

    @operation("network.vlan.create", "Create VLAN", risk="change", params=VlanCreateP, check_mode=True, changes="Create VLAN {vlan_id} named '{name}'")
    def vlan_create(self, p, check_mode=False):
        return self._change([f"vlan {p.vlan_id}", f'name "{p.name}"', "exit"], [f"no vlan {p.vlan_id}"], "show vlans", rf"^\s*{p.vlan_id}\s+{re.escape(p.name)}", check_mode)

    @operation("network.port.access", "Configure access (untagged) port", risk="change", params=AccessPortP, check_mode=True, changes="Untag port {interface} in VLAN {vlan_id}")
    def port_access(self, p, check_mode=False):
        return self._change([f"vlan {p.vlan_id} untagged {p.interface}"], ["! re-apply previous untagged VLAN from 'running-before' backup"], f"show vlans {p.vlan_id}", rf"\b{re.escape(p.interface)}\b.*Untagged", check_mode)

    @operation("network.port.trunk", "Tag VLANs on port", risk="change", params=TrunkPortP, check_mode=True, changes="Tag VLANs {allowed_vlans} on port {interface}")
    def port_trunk(self, p, check_mode=False):
        lines = [f"vlan {vid} tagged {p.interface}" for vid in _expand_vlans(p.allowed_vlans)]
        rb = [f"no vlan {vid} tagged {p.interface}" for vid in _expand_vlans(p.allowed_vlans)]
        return self._change(lines, rb, None, None, check_mode)

    @operation("network.interface.admin", "Enable/disable interface", risk="change", params=IfAdminP, check_mode=True, changes="Set interface {interface} enabled={enabled}")
    def if_admin(self, p, check_mode=False):
        return self._change([f"interface {p.interface} {'enable' if p.enabled else 'disable'}"], [f"interface {p.interface} {'disable' if p.enabled else 'enable'}"], None, None, check_mode)


# ====================================================================== TP-Link JetStream (T-series/Omada CLI)
class TPLinkJetStreamDriver(NetworkDriver):
    key = "tplink_jetstream"
    display_name = "TP-Link JetStream"
    vendor = "TP-Link"
    netmiko_type = "tplink_jetstream"
    cmd_interfaces = "show interface status"
    cmd_vlans = "show vlan brief"
    cmd_routes = "show ip route"
    cmd_save = "copy running-config startup-config"
    cmd_logs = "show logging buffer"
    cmd_arp = "show arp"
    cmd_mac = "show mac address-table all"
    cmd_version = "show system-info"

    def parse_facts(self, out: str) -> dict:
        f = {"vendor": "TP-Link"}
        if m := re.search(r"Firmware Version\s*-?\s*(.+)", out):
            f["firmware"] = m.group(1).strip()
        if m := re.search(r"Serial Number\s*-?\s*(\S+)", out):
            f["serial_number"] = m.group(1)
        if m := re.search(r"Hardware Version\s*-?\s*(.+)", out):
            f["model"] = m.group(1).strip()
        return f

    @operation("network.vlan.create", "Create VLAN", risk="change", params=VlanCreateP, check_mode=True, changes="Create VLAN {vlan_id} named '{name}'")
    def vlan_create(self, p, check_mode=False):
        return self._change([f"vlan {p.vlan_id}", f'name "{p.name}"', "exit"], [f"no vlan {p.vlan_id}"], "show vlan brief", rf"\b{p.vlan_id}\b", check_mode)

    @operation("network.port.access", "Configure access port", risk="change", params=AccessPortP, check_mode=True, changes="Set {interface} untagged member and PVID of VLAN {vlan_id}")
    def port_access(self, p, check_mode=False):
        lines = [f"interface {p.interface}", f"switchport general allowed vlan {p.vlan_id} untagged", f"switchport pvid {p.vlan_id}"]
        if p.description:
            lines.append(f'description "{p.description}"')
        return self._change(lines, [f"interface {p.interface}", f"no switchport general allowed vlan {p.vlan_id}", "! restore previous PVID from backup"], None, None, check_mode)

    @operation("network.port.trunk", "Configure tagged port", risk="change", params=TrunkPortP, check_mode=True, changes="Allow tagged VLANs {allowed_vlans} on {interface}")
    def port_trunk(self, p, check_mode=False):
        return self._change([f"interface {p.interface}", f"switchport general allowed vlan {p.allowed_vlans} tagged"],
                            [f"interface {p.interface}", f"no switchport general allowed vlan {p.allowed_vlans}"], None, None, check_mode)


# ====================================================================== MikroTik RouterOS
class MikroTikDriver(NetworkDriver):
    key = "mikrotik_routeros"
    display_name = "MikroTik RouterOS"
    vendor = "MikroTik"
    netmiko_type = "mikrotik_routeros"
    cmd_running = "/export terse"
    cmd_startup = None
    cmd_version = "/system resource print"
    cmd_interfaces = "/interface print terse"
    cmd_vlans = "/interface bridge vlan print terse"
    cmd_routes = "/ip route print terse"
    cmd_save = None  # RouterOS persists changes immediately
    cmd_logs = "/log print"
    cmd_neighbors = "/ip neighbor print terse"
    cmd_arp = "/ip arp print terse"
    cmd_mac = "/interface bridge host print terse"

    def parse_facts(self, out: str) -> dict:
        f = {"vendor": "MikroTik", "os_name": "RouterOS"}
        if m := re.search(r"version:\s*(\S+)", out):
            f["firmware"] = f["os_version"] = m.group(1)
        if m := re.search(r"board-name:\s*(.+)", out):
            f["model"] = m.group(1).strip()
        return f

    def _config(self, lines: list[str]) -> str:
        conn = self._connect()
        out = ""
        for ln in lines:
            r = conn.send_command(ln, read_timeout=self.timeout)
            if re.search(r"(failure:|bad command|syntax error|expected end of command|input does not match)", r, re.I):
                raise RuntimeError(f"RouterOS rejected '{ln}': {r.strip()}")
            out += f"> {ln}\n{r}"
        return out

    def collect_metrics(self) -> dict[str, float]:
        out = self._show("/system resource print")
        m = {}
        if x := re.search(r"cpu-load:\s*(\d+)%", out):
            m["cpu_pct"] = float(x.group(1))
        tot = re.search(r"total-memory:\s*([\d.]+)(\w+)", out)
        free = re.search(r"free-memory:\s*([\d.]+)(\w+)", out)
        if tot and free:
            conv = {"KiB": 1, "MiB": 1024, "GiB": 1024 * 1024}
            t = float(tot.group(1)) * conv.get(tot.group(2), 1)
            fr = float(free.group(1)) * conv.get(free.group(2), 1)
            m["mem_pct"] = round(100 * (1 - fr / t), 2) if t else 0
        return m

    @operation("network.route.static", "Add static route", risk="critical", params=StaticRouteP, check_mode=True, changes="Add/remove static route {destination} via {next_hop}")
    def static_route(self, p: StaticRouteP, check_mode=False):
        if p.remove:
            line = f"/ip route remove [find dst-address={p.destination} gateway={p.next_hop}]"
            rb = f"/ip route add dst-address={p.destination} gateway={p.next_hop} comment=infrapilot"
        else:
            line = f"/ip route add dst-address={p.destination} gateway={p.next_hop} comment=infrapilot"
            rb = f"/ip route remove [find dst-address={p.destination} gateway={p.next_hop}]"
        return self._change([line], [rb], "/ip route print terse", None if p.remove else re.escape(p.destination), check_mode, save=False)

    @operation("network.interface.admin", "Enable/disable interface", risk="change", params=IfAdminP, check_mode=True, changes="Set interface {interface} enabled={enabled}")
    def if_admin(self, p: IfAdminP, check_mode=False):
        verb, inv = ("enable", "disable") if p.enabled else ("disable", "enable")
        return self._change([f'/interface {verb} [find name="{p.interface}"]'], [f'/interface {inv} [find name="{p.interface}"]'], None, None, check_mode, save=False)
    # VLAN/port operations are intentionally not declared: RouterOS bridge VLAN filtering
    # depends on bridge design (pvid, tagged/untagged, vlan-filtering toggle) and a wrong
    # change can isolate the device. Use a reviewed playbook for these.


def _expand_vlans(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out += list(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    if len(out) > 256 or any(x < 1 or x > 4094 for x in out):
        raise ValueError("VLAN list out of range")
    return out
