"""Point-and-click row actions for the device Manage console.

A read operation returns rows (services, processes, users, VLANs...). For each row the UI offers
follow-up operations with parameters pre-filled from that row. This module only *describes* the
mapping; every action still goes through the normal operation endpoint, so validation, RBAC,
approval policies and audit are exactly the same as when the operation is started by hand.

    map   - parameter name -> column of the row whose value pre-fills it
    fixed - parameter name -> literal value
    when  - column -> allowed values (case-insensitive); the action is hidden for other rows
    tone  - "danger" for actions that stop, delete, disable or reboot something
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class RowAction:
    op: str
    label: str
    map: dict[str, str] = field(default_factory=dict)
    fixed: dict[str, Any] = field(default_factory=dict)
    when: dict[str, list[Any]] = field(default_factory=dict)
    tone: str = "default"


A = RowAction
_svc_win = [
    A("windows.service.start", "Start", {"name": "Name"}, when={"Status": ["Stopped"]}),
    A("windows.service.restart", "Restart", {"name": "Name"}, when={"Status": ["Running"]}),
    A("windows.service.stop", "Stop", {"name": "Name"}, when={"Status": ["Running"]}, tone="danger"),
    A("windows.service.inspect", "Details", {"name": "Name"}),
]
_svc_linux = [
    A("linux.service.start", "Start", {"unit": "unit"}, when={"active": ["inactive", "failed"]}),
    A("linux.service.restart", "Restart", {"unit": "unit"}, when={"active": ["active"]}),
    A("linux.service.stop", "Stop", {"unit": "unit"}, when={"active": ["active"]}, tone="danger"),
    A("linux.service.status", "Status", {"unit": "unit"}),
    A("linux.logs.query", "Logs", {"unit": "unit"}),
]

ROW_ACTIONS: dict[str, list[RowAction]] = {
    # ---------------------------------------------------------------- Windows
    "windows.services.list": _svc_win,
    "windows.processes.list": [A("windows.process.stop", "End process", {"pid": "Id"}, tone="danger")],
    "windows.localusers.list": [
        A("windows.localuser.disable", "Disable", {"username": "Name"}, when={"Enabled": [True]}, tone="danger"),
    ],
    "windows.localgroups.list": [A("windows.localgroup.add_member", "Add member", {"group": "Name"})],
    "windows.ad.users.list": [
        A("windows.ad.user.unlock", "Unlock", {"sam_account_name": "SamAccountName"}, when={"LockedOut": [True]}),
        A("windows.ad.user.reset_password", "Reset password", {"sam_account_name": "SamAccountName"}),
        A("windows.ad.user.set_enabled", "Disable", {"sam_account_name": "SamAccountName"}, {"enabled": False}, when={"Enabled": [True]}, tone="danger"),
        A("windows.ad.user.set_enabled", "Enable", {"sam_account_name": "SamAccountName"}, {"enabled": True}, when={"Enabled": [False]}),
        A("windows.ad.group.add_member", "Add to group", {"member": "SamAccountName"}),
    ],
    "windows.ad.groups.list": [
        A("windows.ad.group.add_member", "Add member", {"group": "Name"}),
        A("windows.ad.group.remove_member", "Remove member", {"group": "Name"}, tone="danger"),
    ],
    "windows.tasks.list": [
        A("windows.task.run", "Run now", {"task_name": "TaskName", "task_path": "TaskPath"}),
        A("windows.task.disable", "Disable", {"task_name": "TaskName", "task_path": "TaskPath"}, when={"State": ["Ready", "Running"]}, tone="danger"),
        A("windows.task.enable", "Enable", {"task_name": "TaskName", "task_path": "TaskPath"}, when={"State": ["Disabled"]}),
    ],
    "windows.features.list": [
        A("windows.feature.install", "Install", {"name": "Name"}, when={"Installed": [False]}),
        A("windows.feature.uninstall", "Uninstall", {"name": "Name"}, when={"Installed": [True]}, tone="danger"),
    ],
    "windows.shares.list": [
        A("windows.share.access.get", "Permissions", {"name": "Name"}),
        A("windows.share.access.grant", "Grant access", {"name": "Name"}),
        A("windows.share.remove", "Remove share", {"name": "Name"}, tone="danger"),
    ],
    "windows.firewall.rules.list": [
        A("windows.firewall.rule.update", "Edit", {"display_name": "DisplayName"}),
        A("windows.firewall.rule.set_enabled", "Disable", {"display_name": "DisplayName"}, {"enabled": False}, when={"Enabled": ["True"]}, tone="danger"),
        A("windows.firewall.rule.set_enabled", "Enable", {"display_name": "DisplayName"}, {"enabled": True}, when={"Enabled": ["False"]}),
        A("windows.firewall.rule.remove", "Delete", {"display_name": "DisplayName"}, tone="danger"),
    ],
    "windows.dns.zones.list": [A("windows.dns.records.list", "Records", {"zone": "ZoneName"}), A("windows.dns.record.add", "Add record", {"zone": "ZoneName"})],
    "windows.dns.records.list": [A("windows.dns.record.remove", "Remove", {"name": "HostName", "type": "RecordType"}, tone="danger")],
    "windows.dhcp.scopes.list": [
        A("windows.dhcp.leases.list", "Leases", {"scope_id": "ScopeId"}),
        A("windows.dhcp.reservation.add", "Add reservation", {"scope_id": "ScopeId"}),
    ],
    "windows.gpo.list": [
        A("windows.gpo.inspect", "Inspect", {"name": "DisplayName"}),
        A("windows.gpo.report", "Report", {"name": "DisplayName"}),
        A("windows.gpo.link", "Link to OU", {"name": "DisplayName"}),
    ],
    # ---------------------------------------------------------------- Linux
    "linux.services.list": _svc_linux,
    "linux.processes.top": [
        A("linux.process.kill", "Terminate", {"pid": "pid"}, {"signal": "TERM"}, tone="danger"),
        A("linux.process.kill", "Kill", {"pid": "pid"}, {"signal": "KILL"}, tone="danger"),
    ],
    "linux.users.list": [
        A("linux.user.add_group", "Add to group", {"username": "username"}),
        A("linux.user.delete", "Delete", {"username": "username"}, tone="danger"),
    ],
    "linux.updates.pending": [A("linux.package.install", "Upgrade", {"packages": "package"})],
    "linux.firewall.rules": [
        A("linux.firewall.rule.delete", "Delete", {"action": "action", "port": "port", "protocol": "protocol", "source": "source"},
          when={"manageable": [True]}, tone="danger"),
    ],
    # ---------------------------------------------------------------- Network
    "network.interfaces": [
        A("network.interface.admin", "Shut down", {"interface": "name"}, {"enabled": False}, when={"status": ["connected", "notconnect", "up"]}, tone="danger"),
        A("network.interface.admin", "Enable", {"interface": "name"}, {"enabled": True}, when={"status": ["disabled", "err-disabled", "down"]}),
        A("network.interface.description", "Describe", {"interface": "name"}),
        A("network.port.access", "Set access VLAN", {"interface": "name"}),
        A("network.port.trunk", "Set trunk", {"interface": "name"}),
    ],
    # ---------------------------------------------------------------- Firewalls
    "firewall.rules.list": [
        A("firewall.rule.set_enabled", "Disable", {"policy_id": "id", "rule_name": "name"}, {"enabled": False}, when={"enabled": [True]}, tone="danger"),
        A("firewall.rule.set_enabled", "Enable", {"policy_id": "id", "rule_name": "name"}, {"enabled": True}, when={"enabled": [False]}),
        A("firewall.rule.delete", "Delete", {"policy_id": "id"}, tone="danger"),
    ],
    # ---------------------------------------------------------------- Virtualization
    "virt.vms": [
        # Proxmox rows (node/vmid/type/status)
        A("virt.vm.power", "Start", {"node": "node", "vmid": "vmid", "type": "type"}, {"action": "start"}, when={"status": ["stopped"]}),
        A("virt.vm.power", "Shut down", {"node": "node", "vmid": "vmid", "type": "type"}, {"action": "shutdown"}, when={"status": ["running"]}, tone="danger"),
        A("virt.vm.power", "Reboot", {"node": "node", "vmid": "vmid", "type": "type"}, {"action": "reboot"}, when={"status": ["running"]}, tone="danger"),
        A("virt.vm.snapshots", "Snapshots", {"node": "node", "vmid": "vmid", "type": "type"}),
        A("virt.vm.snapshot.create", "Snapshot", {"node": "node", "vmid": "vmid", "type": "type"}),
        # vCenter rows (vm/power_state)
        A("virt.vm.power", "Power on", {"vm": "vm"}, {"action": "start"}, when={"power_state": ["POWERED_OFF"]}),
        A("virt.vm.power", "Guest shutdown", {"vm": "vm"}, {"action": "guest-shutdown"}, when={"power_state": ["POWERED_ON"]}, tone="danger"),
        A("virt.vm.power", "Guest reboot", {"vm": "vm"}, {"action": "guest-reboot"}, when={"power_state": ["POWERED_ON"]}, tone="danger"),
    ],
    "virt.vm.snapshots": [
        A("virt.vm.snapshot.rollback", "Roll back", {"snapname": "snapname"}, tone="danger"),
        A("virt.vm.snapshot.delete", "Delete", {"snapname": "snapname"}, tone="danger"),
    ],
}


# "New …" buttons shown above a view's table (operations that add an item to that view).
VIEW_ACTIONS: dict[str, list[tuple[str, str]]] = {
    "windows.firewall.rules.list": [("windows.firewall.rule.create", "Add rule")],
    "linux.firewall.rules": [("linux.firewall.rule.add", "Add rule")],
    "linux.firewall.status": [("linux.firewall.rule.add", "Add rule")],
    "windows.localusers.list": [("windows.localuser.create", "New user")],
    "windows.ad.users.list": [("windows.ad.user.create", "New user")],
    "windows.ad.ous.list": [("windows.ad.ou.create", "New OU")],
    "windows.shares.list": [("windows.share.create", "New share")],
    "windows.dns.records.list": [("windows.dns.record.add", "Add record")],
    "windows.gpo.list": [("windows.gpo.create", "New GPO")],
    "linux.users.list": [("linux.user.create", "New user")],
    "network.vlans": [("network.vlan.create", "New VLAN")],
    "network.routes": [("network.route.static", "Static route")],
    "firewall.rules.list": [("firewall.rule.create", "Add policy")],
    "firewall.objects.list": [("firewall.object.address.create", "New address")],
    "firewall.nat.list": [("firewall.nat.vip.create", "New VIP")],
    "virt.vm.snapshots": [("virt.vm.snapshot.create", "New snapshot")],
}


def view_actions_for(read_op: str, available: dict) -> list[dict]:
    return [{"op": op, "label": label} for op, label in VIEW_ACTIONS.get(read_op, []) if op in available]


def actions_for(read_op: str, available: dict) -> list[dict]:
    """Row actions for ``read_op`` limited to operations the device's driver supports.

    Parameters the target operation does not declare are dropped, so one mapping can serve
    several vendors (e.g. FortiGate ``policy_id`` vs Sophos ``rule_name``).
    """
    out = []
    for a in ROW_ACTIONS.get(read_op, []):
        spec = available.get(a.op)
        if spec is None:
            continue
        fields = set(spec.params.model_fields)
        d = asdict(a)
        d["map"] = {k: v for k, v in a.map.items() if k in fields}
        d["fixed"] = {k: v for k, v in a.fixed.items() if k in fields}
        if a.map and not d["map"]:
            continue  # the row columns belong to another vendor's version of the operation
        d["risk"] = {"read": "low", "change": "medium", "critical": "critical"}[spec.risk]
        out.append(d)
    return out
