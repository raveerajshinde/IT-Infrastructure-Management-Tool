# Integration Drivers and Capability Matrix

Each driver declares exactly the operations it implements. Anything not listed for a driver is
reported as **unsupported** (never as success). Risk: R = read-only, C = change (approval in
production by default), X = critical (always needs approval). ✓dry = supports check mode.

## Windows Server 2016/2019/2022/2025, Windows 10/11 — `windows` (WinRM/PSRP, pypsrp)

Connection: WinRM/PSRP over **HTTP 5985** (message encryption via Negotiate/NTLM/Kerberos/CredSSP; Basic refused) or **HTTPS 5986**, chosen by the device port or forced by the credential.

| Area | Operations |
|---|---|
| Services | list (R), inspect (R), start / stop / restart (C, ✓dry, verified by reading state back) |
| Roles & features | list (R), install / uninstall (X, ✓dry via `-WhatIf`) — Windows Server only |
| Folders & SMB | create folder (C, ✓dry), list shares (R), create share with Full/Change/Read ACL (C, ✓dry), remove share (X), get / grant share permission (R/C) |
| NTFS | get ACL (R), grant/deny ACE with inheritance (C, ✓dry, verified) |
| Local accounts | list users / groups (R), create user (C, password sealed in vault), disable user (C), add group member (C) |
| Storage | disks and volumes with size, free space, health (R) |
| Event Viewer | query by log, level, time range, max events (R) |
| Scheduled tasks | list (R), run / enable / disable (C) |
| Certificates | list a LocalMachine store, filter by expiry (R) |
| Windows Firewall | profiles (R), rules with ports/remote addresses, filter by name/direction, include disabled (R), create rule (C, ✓dry), edit action/ports/remote address/profile (C, before/after recorded), enable/disable (C), delete (C, full definition kept for re-creation). WinRM rules are protected: InfraPilot refuses to change the rules it connects through |
| IIS | sites & app pools (R), start/stop site, recycle pool (C) — needs IIS management tools |
| Active Directory | users (R), create user (C), enable/disable (C), unlock (C), reset password (C), groups (R), add/remove member (C, verified), OUs (R), create OU (C) — needs RSAT-AD-PowerShell |
| DNS | zones (R), records (R), add A/CNAME (C), remove record (X) — needs DnsServer module |
| DHCP | scopes with utilisation (R), leases (R), add reservation (C) — needs DhcpServer module |
| Group Policy | list (R), inspect links (R), create (C), link to OU/domain (X), set registry-based policy value (X), HTML/XML report (R), GPUpdate local or remote (C) — needs GroupPolicy module |
| System | system information incl. pending reboot (R), reboot with delay and reason (X, cancellable with `shutdown /a`) |
| Processes | top processes by CPU or memory (R), end process by PID (C, verified) |
| Updates & software | pending Windows updates via the Windows Update Agent (R), installed software from the Uninstall registry keys (R) |
| Network | adapters, IP configuration, DNS servers (R) |
| Health | CPU, memory, fullest disk, uptime |

Not implemented (by design, too destructive for unattended automation): disk initialise/format/partition,
certificate import/renewal, arbitrary GPO setting editing beyond registry-based policies.

## Linux (Ubuntu, Debian, RHEL-compatible, SUSE) — `linux` (SSH, paramiko)

systemd: list, status (R), start/stop/restart/enable/disable (C, ✓dry, verified) · packages via
apt/dnf/yum/zypper: query (R), install (C, ✓dry), remove (X, ✓dry) · users: list (R), create (C, ✓dry),
delete (X), group create, add user to group (C) · files: stat (R), create directory with mode/owner
(C, ✓dry), chmod / chown (C, previous value recorded) · SSH: effective sshd config (R), set an
allow-listed sshd option via drop-in, validated with `sshd -t` and auto-reverted on failure (X, ✓dry) ·
firewall (ufw or firewalld): status (R), rule list incl. ufw comments and firewalld ports/services/rich rules (R), add allow/deny/reject rule for a port with optional source and comment (C, ✓dry, verified), delete rule (C, ✓dry, verified) — the SSH port InfraPilot uses can never be denied or have its allow rule removed · disks/filesystems/mounts (R) ·
journal logs (R) · top processes (R) · signal/kill a process (C, never PID 1, verified) · system
information incl. reboot-required flag (R) · reboot with delay and message (X, argv-only `shutdown`) ·
pending package updates incl. security flag (R) · network interfaces and routes (R) · cron jobs and
systemd timers (R) · health metrics (R) · approved maintenance commands (C).

## Network (SSH CLI via Netmiko)

| Operation | Cisco IOS/IOS-XE `cisco_ios` | Aruba AOS-CX `aruba_aoscx` | HPE ProCurve `hp_procurve` | TP-Link JetStream `tplink_jetstream` | MikroTik `mikrotik_routeros` |
|---|---|---|---|---|---|
| Facts, interfaces, VLANs, routes (R) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Config backup running/startup (R) | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | `/export` |
| Create VLAN (C, ✓dry) | ✓ | ✓ | ✓ | ✓ | — |
| Delete VLAN (X) | ✓ | — | — | — | — |
| Access port (C, ✓dry) | ✓ | ✓ | ✓ (untagged) | ✓ (PVID) | — |
| Trunk / tagged (C, ✓dry) | ✓ | ✓ | ✓ (tagged) | ✓ | — |
| Interface enable/disable (C) | ✓ | ✓ | ✓ | — | ✓ |
| Interface description (C) | ✓ | — | — | — | — |
| Static route (X) | ✓ | — | — | — | ✓ |
| Device log (R) | ✓ | ✓ | ✓ | ✓ | ✓ |
| Neighbours LLDP/CDP (R) | CDP | LLDP | LLDP | — | ✓ |
| ARP table / MAC table (R) | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ (bridge hosts) |
| Save running → startup (C) | ✓ | ✓ | ✓ | ✓ | — (persists immediately) |

An operation only appears for a platform when that platform has the CLI command behind it.

Every change captures running-config before and after, saves the configuration
(`write memory` / `copy running-config startup-config`), stores the diff and verifies by reading
state back. MikroTik VLAN/port operations are intentionally not offered: bridge VLAN filtering
depends on site design and a wrong change can isolate the device — use a reviewed playbook.
NETCONF is not used; all supported vendors are driven through their CLI or REST APIs.

**Generic SNMPv3** (`snmp_generic`, monitoring only) — access points, storage arrays and any other
SNMP-capable device: availability, system info, interface table (status, speed, octets),
CPU/memory/storage from HOST-RESOURCES-MIB.

## Firewalls

| Operation | FortiGate (REST, `fortigate`) | Sophos Firewall/XGS (XML API, `sophos_xgs`) |
|---|---|---|
| Interfaces, zones (R) | ✓ (per VDOM) | ✓ |
| Routes (R) | live routing table | static routes only (API limitation) |
| VPN status (R) | IPsec tunnels + phase-2 status, SSL-VPN sessions | IPsec configuration (no live state via API) |
| Rules list (R) / ANY-rule analysis (R) | ✓ / ✓ | ✓ / ✓ |
| NAT & objects (R) | VIPs, IP pools, addresses, groups, services | NAT rules, hosts, services |
| Logs (R) | memory / disk / FortiAnalyzer: traffic, event, IPS, AV, web filter | **not available via API** — use syslog |
| Config backup (R) | full configuration | API object snapshot (not a restorable appliance backup) |
| Enable/disable rule (X) | ✓ verified, full config before/after + diff | ✓ verified, snapshot before/after + diff |
| Create / delete rule (X) | ✓ (new rules are appended; reorder on the device) | — |
| Create address object (C), VIP / DNAT (X) | ✓ | — |

ANY-rule analysis flags enabled accept rules with source, destination or service = ANY
(critical when all three, or ANY from a WAN/untrust zone), and rules without logging.

## Virtualization and storage

* **Proxmox VE** (`proxmox`, API token): nodes, VMs/containers with CPU/memory, storage utilisation,
  backup jobs and recent vzdump task results (R); VM/CT start/shutdown/stop/reboot/suspend/resume (X,
  waits for the task and verifies state); snapshots: list (R), create incl. optional RAM state (C,
  verified), roll back (X), delete (X).
* **VMware vCenter** (`vmware_vcenter`, vSphere 7.0U2+ REST): hosts, VMs, datastores with utilisation
  (R); power on/off/reset/suspend and guest shutdown/reboot (X). Performance counters are not exposed
  by the REST API — only datastore utilisation is collected as a metric.
* Storage arrays: monitored via the generic SNMPv3 driver. Backup systems other than Proxmox
  vzdump (e.g. Veeam) have no adapter yet.

## Row actions (Manage console)
`backend/app/drivers/actions.py` maps a read operation's result columns to follow-up operations
(e.g. *List services* → Start/Stop/Restart with `name` from the `Name` column). Actions are filtered
per driver so only supported operations and parameters are offered, and they run through the normal
job pipeline. A test verifies every mapping references real operations and parameters.

## Adding a vendor

Create a `Driver` subclass, declare operations with `@operation(...)` (parameter model, risk, check
mode, secret params, change description), implement `test_connection`, `collect_facts`,
`collect_metrics`, register it in `app/drivers/registry.py`, and add mock-device tests like those in
`backend/tests/test_drivers_mock_devices.py`.
