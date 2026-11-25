# Build and Verification Status (release 1.1.1)

**1.1.1 (fix):** *Collect all GPOs for reporting* failed with "storing its result failed: expected string or bytes-like
object, got 'list'" when PowerShell returned the `Get-GPOReport -All` output as several strings. The collector now joins
the output into one document, and the parser accepts a list (chunks of one report or one report per GPO). Regression
tests: `test_report_returned_as_list_by_powershell`, `test_collect_job_with_list_output`.

## Release 1.1.0

**1.1.0:** Group Policy reporting, Active Directory inventory, IT audit & compliance engine, Report Center and the
new navigation (see MODULES_1.1.md). Verified in the build environment:

| Area | How |
|---|---|
| Backend | 204 automated tests, all passing (23 new in 1.1: `test_gpo.py`, `test_ad.py`, `test_compliance.py`, `test_report_center.py`), with the SQL Server dialect and single-result-set guards active for every statement |
| GPO parsing and analysis | A fictitious multi-GPO `Get-GPOReport -All` file (`docs/samples/sample-gpo-report.xml`, UTF-8 and UTF-16): statuses, domain-root rule for password policy, precedence with enforced links and block inheritance (collector data), conflicts/duplicates, version diffs, DTD/entity rejection, collection job end-to-end with a mocked PSRP transport |
| AD | Sync against an in-memory directory with the real AD schema (ldap3 MOCK_SYNC, OFFLINE_AD_2012_R2): binary GUID/SID decoding, FILETIME/generalized time, recursive and nested privileged groups, change detection between syncs, reports, bulk preview → jobs |
| IT audit | Frameworks seeded; automated results from real fixture data; "not assessed" when data is missing; evidence SHA-256 verification incl. tamper detection; finding lifecycle and segregation-of-duties rules; approval lock; report sections |
| Reports | All 12 templates rendered in PDF, Excel, CSV and HTML; schedules with e-mail attachment (SMTP mocked); history download and permission checks. PDF layout reviewed visually (rasterised pages) |
| Migration | `0004` adds 15 tables only; upgrade → downgrade → upgrade on SQLite; renders valid T-SQL (`docs/schema-mssql.sql`, file content as VARBINARY(MAX)) |
| UI | TypeScript strict build; existing 17 Vitest tests; new pages exercised with the real API (SQLite, seeded sample data) in headless Chrome: dashboard posture row, GPO inventory/baseline/detail/conflicts, AD users, assessment detail, Report Center |

Not verifiable here — verify on site: GPO collection, RSoP, Backup-GPO/Restore-GPO against a real domain controller
(PowerShell scripts tested with mocked transports only); LDAPS against your DCs (certificate chain, paged results on a
large directory); SMTP delivery of scheduled reports; PDF rendering of very large GPO estates (>500 GPOs). New
frontend pages have no unit tests of their own (verified end-to-end only).

Known limitations of 1.1: readable names for Administrative Templates require English GPMC reports; uploaded reports
lack link order/block inheritance (flagged as approximate); AD "recently deleted" is detected between syncs only;
no CVE/vulnerability feed, syslog collection, network topology map, or Palo Alto/Cisco ASA adapters yet (see ROADMAP.md).

## Release 1.0.9

**1.0.9:** device configuration backups can be written to a folder on the server (Settings → Backup → Folder on the
server), in addition to the existing SMB share option. Covered by `backend/tests/test_folder_export.py` (path
validation, full/masked copies, incremental + "copy all again", latest_<kind>.cfg, retention, worker hook). The
container bind mounts (`/srv/infrapilot-exports`, `/mnt`, `/media`) were validated with `docker compose config`
but not exercised on a running Docker host in this build environment.


This file records what was verified in the build environment and what still needs to be verified
on target infrastructure. It should be read before production rollout.

## Verified in the build environment

| Area | How |
|---|---|
| SQL Server compatibility | Every SQL statement executed by the test suite (API, services and all background worker routines) is also compiled for the SQL Server dialect and rejected if it contains constructs SQL Server does not accept (boolean `IS 1`, `LIMIT`, `NULLS LAST`, `ILIKE`). Added in 1.0.2 after a field report of `Incorrect syntax near '1'` on Automation → templates. Since 1.0.8 the test database also enforces SQL Server's one-open-result-set rule (a query started while another query's rows are unread fails the test), after a field report of `Connection is busy with results for another command`; production connections additionally enable MARS (`MARS_Connection=yes`) |
| Backend (API, services, worker logic) | 174 automated tests (`cd backend && pytest`), all passing: auth/lockout/MFA/CSRF/sessions, RBAC incl. device-group scoping, inventory CRUD/validation/import/export, vault encryption, secret redaction, audit hash chain and tamper detection, approval policies, segregation of duties, emergency changes, maintenance windows (incl. auto-approve), approval expiry, check mode, secret job parameters, cancellation, partial failures, stale-job recovery, concurrent job claiming, monitoring/alert dedupe/resolve, scheduled config backups, Zabbix sync, LDAP role mapping and default-deny, settings validation, CLI, recurring schedules (cron parsing, run-as-owner, approval still applies, double-launch protection, auto-pause on disabled owner), reports (JSON/CSV/XLSX, permission filtering), approval-policy delete guard, dashboard aggregates, row-action registry integrity |
| Drivers | Mock-device tests with faked transports: Windows (PSRP parameter binding, no interpolation, missing RSAT module → unsupported), Linux (sudo, quoting, package manager, verification), Cisco (before/after config, verification, check mode), FortiGate and Sophos (HTTP mock APIs), Proxmox; every driver's operation catalogue validated |
| Ansible | All 8 playbooks pass `ansible-playbook --syntax-check`; the runner was executed end-to-end with real ansible-runner (local connection): isolation directory created and removed, success and failure detection |
| SQL Server schema | Alembic migration renders valid T-SQL (`docs/schema-mssql.sql`, 29 tables + audit trigger; migration 0002 adds `job_schedules`); upgrade/downgrade/upgrade and `alembic check` on SQLite |
| Frontend | TypeScript strict build, 17 Vitest tests, production Vite build |
| End-to-end UI | Real API + worker + built UI driven by headless Chrome: sign-in, onboarding wizard, credential and device creation, connectivity test, change preview → approval required → second user created in the UI → forced password change → approval → worker execution → job result with verification/rollback → audit verification; all pages loaded with no failed API calls or console errors. Release 1.0.0 final additionally drove the new dashboard (light/dark), the Manage console (Linux services → Start pre-filled → change preview with approval; Proxmox VM → Snapshots → Roll back with node/vmid/snapshot carried over; FortiGate policies with Enable/Disable/Delete), Schedules (list, editor with cron preview), Reports and approval Policies; Windows/Linux host-firewall rule views with Add/Edit/Enable/Disable/Delete; Settings → Branding with live preview, branded sign-in page, sidebar, dashboard and tab title |
| Installer scripts | `bash -n` and ShellCheck (warning level) clean; helper unit tests pass; `docker compose config` validates the stack |

## Not verifiable here — verify on your infrastructure

| Item | Reason / action |
|---|---|
| Container image builds and the full `install.sh` run | The build environment blocks Docker Hub and mcr.microsoft.com. Run `tests/installer/run-vm-tests.sh` (Multipass) on clean Ubuntu 22.04 and 24.04 VMs: it installs unattended, checks health, signs in, writes data, backs up, restores, re-runs the installer (idempotent upgrade), reboots and purges. |
| Runtime against SQL Server 2022 | The schema renders correctly and SQL Server-specific code paths (sp_getapplock, trigger, DENY, login bootstrap) are dialect-guarded, but they run for the first time in the VM test. |
| Real devices | Drivers were exercised against faithful mocks, not real equipment. Start in a lab: run every read-only operation first, then changes with check mode, then real changes on non-production devices. Vendor CLI output varies by firmware; parsing for facts/interfaces may need small adjustments per model. |
| LDAPS against your domain controllers, SMTP relay, Zabbix/LibreNMS | Mocked in tests; use the Test buttons in Settings/Integrations. |

## Known limitations (documented, by design or deferred)

* No NETCONF; network devices are managed through vendor CLI (Netmiko) and REST/XML APIs.
* MikroTik: no VLAN/port changes (bridge VLAN filtering is design-specific). Aruba/HP/TP-Link: no VLAN delete or static routes.
* Sophos API: no log retrieval, no full appliance backup (object snapshot only), no rule creation.
* Windows: no disk initialise/format, no certificate import/renewal.
* VMware: no performance counters via REST. Backup integration: Proxmox vzdump only.
* Network-share backup: verified with unit tests (OpenSSL-compatible encryption checked against the `openssl` CLI, upload sets, masking, retention safety) and against an SMB2 test server for authentication and folder creation; file writes were not verified against a real Windows/Samba share in the build environment.
* Script library: PowerShell/shell/switch CLI execution tested with mocked transports (parameter binding, quoting, rejected-line handling); the FortiGate configuration-script upload follows the FortiOS REST API (`monitor/system/config-script/upload`) but was not run against a real FortiGate in the build environment — try a harmless script on a lab unit first.
* Schedules use UTC cron expressions; there is no per-schedule time zone.
* New 1.0.0-final operations (Windows reboot/processes/updates/software, Linux reboot/kill/updates/network/cron, network logs/neighbours/ARP/MAC/save, Proxmox snapshots) were tested against mocks only — verify on lab devices first, as for all operations.
* Rate limiting in the API is per process (nginx limits apply globally).
* Previous partial build: the earlier attempt's conflicting backend modules and tests were moved
  unchanged to `/home/claude/infrapilot-archive-2026-11-12/` in the build workspace (not part of the release).
