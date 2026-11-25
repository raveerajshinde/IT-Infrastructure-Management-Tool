# Architecture Assessment and Implementation Plan

## Assessment of the existing platform (1.0.x)

InfraPilot already provided most of the infrastructure foundation the specification asks for:

| Specification module | State before 1.1 |
|---|---|
| 4 Server management (Windows/Linux) | Implemented: WinRM/PSRP and SSH drivers with services, processes, updates, software, tasks, local users, event logs, IIS, firewall, storage, SSH configuration audit, cron; maintenance windows, groups, sites, tags, bulk operations with approval |
| 5 Firewall | Implemented for **FortiGate** (REST) and **Sophos XGS** (XML API): inventory, policies, rule analysis, VPN/interface reads where the API exposes them, config backup/diff. Unsupported operations are declared, never faked |
| 6 Switches/routers/APs | Implemented for Cisco IOS/XE, Aruba AOS-CX, HPE ProCurve, TP-Link JetStream, MikroTik (Netmiko) and generic SNMPv3: interfaces, VLANs, neighbours, MAC/ARP, config backup/diff |
| 8 Change and audit trail | Implemented: hash-chained, DB-trigger protected audit log; before/after state and diffs on jobs |
| 9 Alerting | Implemented: rules, thresholds, dedupe, acknowledge, escalation e-mail, notifications |
| 10 RBAC | Implemented: permissions, device-group scoping, MFA, sessions, approvals |
| 12 UI | React/Tailwind portal with dark mode, global search, notification centre |
| 13/14 Database and integrations | SQL Server via Alembic; encrypted vault; Zabbix/LibreNMS integrations |

Missing or partial: Active Directory inventory and reports (only individual AD operations existed), readable GPO
reporting (only raw `Get-GPOReport` output), an IT audit/compliance engine, a report center with scheduling and
PDF output, and the navigation structure from the specification.

## Phase 1.1 — delivered in this release
1. **Group Policy** (high priority): collection over WinRM or XML upload, readable settings in 19 categories,
   ~100-rule baseline with honest statuses, precedence per OU, conflicts/duplicates/OU differences, comparison,
   history with alerts, gpresult/RSoP, backup and approved restore with dry-run diff, 15-section reports.
2. **IT audit engine** (high priority): ISO 27001:2022, CIS v8, NIST CSF 2.0, RBI frameworks, 24 automated
   checks with stored evidence, manual results, findings lifecycle, evidence repository with integrity checks,
   approval with segregation of duties, audit reports.
3. **Active Directory**: LDAPS inventory, 13 reports, change detection and alerts, approved bulk actions.
4. **Report Center**: 12 templates, PDF/Excel/CSV/HTML, scheduled e-mail delivery, report history.
5. **UI**: grouped navigation per specification, breadcrumbs, reusable data tables (sort, search, pagination,
   column selection), security-posture dashboard row.

## Next phases (not in this release)
| Phase | Scope | Notes |
|---|---|---|
| 1.2 Firewall vendors | Palo Alto (PAN-OS XML API), Cisco ASA/FTD (FMC REST), Sophos log/traffic reports | Adapter framework exists (`app/drivers/firewall.py`); each vendor needs lab access to validate |
| 1.2 Network topology | LLDP/CDP-based topology map, port-to-device mapping, rogue device detection from MAC/ARP vs inventory | Data is already collected per device; needs aggregation and a graph view |
| 1.3 Event collection | Syslog receiver and Windows event forwarding for failed logons/privileged use dashboards | Requires a log store sized for your volume |
| 1.3 Vulnerability data | Import from a scanner (Nessus/OpenVAS/Defender) and vendor firmware advisories | Needs a licensed or internal feed |
| 1.3 GPO editing | Guided remediation (set a baseline value in a GPO with preview/approval) | `windows.gpo.set_registry` exists for registry-based policies |
| Later | Per-schedule time zones, report branding templates, SAML/OIDC sign-in | |
