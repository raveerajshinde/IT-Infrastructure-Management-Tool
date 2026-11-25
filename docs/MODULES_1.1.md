# InfraPilot 1.1 — Group Policy, Active Directory, IT Audit and Report Center

Administrator guide for the modules added in 1.1. Everything here runs on top of the existing platform:
the same RBAC, approval policies, maintenance windows, jobs, audit trail and alerting apply.

---

## 1. Roles and permissions

New permissions: `gpo:read`, `gpo:manage`, `ad:read`, `ad:manage`, `compliance:read`, `compliance:manage`,
`compliance:approve`, `reports:read`, `reports:manage`. Built-in roles that include "all read permissions"
receive the new `:read` permissions automatically when the update runs.

| Role (new in 1.1) | Purpose |
|---|---|
| Active Directory Administrator | AD and GPO inventory and reports; account actions as approved Windows jobs |
| Security Administrator | Alerts, GPO baseline exclusions, AD sync, findings and evidence, scheduled reports |
| Auditor / Compliance Officer | Runs and **approves** assessments, accepts risks; read-only on infrastructure |
| Read-only Management User | Dashboards, reports, audit/GPO/AD views; no operational access |

Existing roles map to the roles named in the specification as follows: *Super Administrator* (unchanged),
*Infrastructure Administrator* = IT Infrastructure Administrator, *Network/Firewall Administrator* = Network
Administrator, *IT Support Engineer* = Helpdesk Technician, *Auditor / Read Only* (kept for compatibility).
Roles were not renamed so existing assignments keep working.

Segregation of duties enforced by the server (not only the UI):
* an assessment cannot be approved by its author;
* a finding cannot be closed by its remediation owner (independent verification);
* risk acceptance needs `compliance:approve`, a reason and a future review date, and cannot be granted by the owner.

---

## 2. Group Policy

### 2.1 Getting data
**Collect from a domain controller (recommended).** Group Policy → *Collect from DC*, pick a Windows device that
is a DC or has GPMC/RSAT (`GroupPolicy` and `ActiveDirectory` PowerShell modules) and WinRM credentials. The job
(`windows.gpo.collect`, read-only) runs:

* `Get-GPOReport -All -ReportType Xml` — every GPO and setting;
* `Get-GPInheritance` for the domain root and every OU — exact link order, enforced links, block inheritance and
  the precedence Windows itself computes;
* `Get-ADDomain` / `Get-ADDomainController` — domain and DC information;
* a SYSVOL check — GPOs whose SYSVOL folder is missing and SYSVOL folders without an AD object (orphans).

The account needs only read access to GPOs (Authenticated Users can read them by default) and to SYSVOL.
Schedule it daily under Automation → Schedules (operation *Collect all GPOs for reporting*).

**Upload.** Run `Get-GPOReport -All -ReportType Xml -Path C:\Temp\gpos.xml` and upload the file (UTF-16 from
PowerShell is fine, up to 64 MB). Uploaded reports have no link order, block inheritance or SYSVOL data; the
UI and reports say that precedence is *derived from links (approximate)*.

Each collection is stored; each GPO version is stored once (SHA-256 of the report without the read time). When a
GPO is created, changed or deleted between collections an alert (*GPO changed: …*) is raised and the change is
listed under Group Policy → History with a setting-level before/after comparison.

### 2.2 Reading the results
* **GPO Inventory** — status, links (enforced/disabled/site), settings count, non-compliant count, and flags:
  *Unlinked*, *All links disabled*, *Empty*, *All settings disabled*, *Version mismatch AD/SYSVOL*, *Orphaned*,
  *No security filtering*.
* **GPO detail** — Computer and User configuration separately, grouped into Password Policy, Account Lockout,
  Kerberos, Windows Defender, Firewall, Windows Update, BitLocker, USB Restrictions, RDP, PowerShell, Microsoft
  Edge, Google Chrome, User Rights, Audit Policy, Security Options, Windows Services, Event Log, Administrative
  Templates and Preferences & Other. Each setting shows policy name, category, configured value, expected value
  (when the baseline defines one), status, risk, explanation and recommendation.
* **GPO Compliance** — the baseline per OU using the *effective* (winning) value.
* **Conflicts & Precedence** — conflicting values for the same OU (with the winner), duplicates, settings that
  differ across OUs, and the precedence list for each OU.
* **GPO Comparison** — two to ten GPOs side by side.
* **History** — collections and before/after diffs.

Status vocabulary — a missing setting is **never** treated as insecure:

| Status | Meaning |
|---|---|
| Compliant | Configured and meets the baseline |
| Non-compliant | Configured and does not meet the baseline (risk shown) |
| Not configured | No linked, enabled GPO sets it; it may be set locally or by other tools — verify separately |
| Not applicable | Cannot take effect where it is (e.g. password/lockout policy outside the domain root affects only local accounts; disabled GPO half; unlinked GPO) or excluded by an administrator |
| Unknown | Configured, but the value could not be interpreted |
| Configured (no baseline) | Informational; the baseline has no expectation for it |

### 2.3 The baseline
Around 100 rules aligned with the CIS Microsoft Windows Server Benchmark (Level 1) and the Microsoft Security
Baseline: password and lockout policy, Kerberos, security options (LM/NTLM, SMB/LDAP signing, UAC, anonymous
access), legacy and advanced audit policy, user rights, services, event log size, Windows Firewall profiles,
Defender, Windows Update/WSUS over HTTPS, RDP (NLA, encryption, saved passwords), PowerShell logging, WinRM
Basic/unencrypted, SMBv1, WDigest, LLMNR, AutoRun/AutoPlay, BitLocker start-up authentication, Edge SmartScreen,
Chrome Safe Browsing and password manager. A rule that does not apply to your organisation can be **excluded with
a reason** (Group Policy → GPO Compliance → *Exclude…*); exclusions are audited and shown as *Not applicable*.

Readable names come from the English GPMC report. Reports produced in another language still parse, but
Administrative Template settings then show as *Configured (no baseline)*.

### 2.4 Resultant policy (gpresult)
Operation *Resultant policy (gpresult)* (`windows.gpo.rsop`) on a Windows device runs
`Get-GPResultantSetOfPolicy` for a computer (and optionally a user) and lists which GPOs applied and, for each
one that did not, why: security filtering, WMI filter false, disabled half, disabled link, version mismatch, or
superseded/empty. Client-side extension errors are listed.

### 2.5 Backup and restore
Group Policy → Backup & Restore: choose the DC, the GPO and a folder on that server.
* *Back up GPO* — `Backup-GPO` (change risk); the backed-up version is also stored in the history.
* *List backups in folder* — reads `bkupInfo.xml` of each backup.
* *Restore* — `Restore-GPO`, **critical** risk. Run it as a **dry-run** first: the job compares the current GPO
  with the backup's report and lists every setting that would change, without changing anything. The real
  restore requires approval per your policies, captures the GPO before and after, and stores both versions.

### 2.6 Reports
Group Policy → GPO Reports, or Reports → Report Center → *Complete GPO Report*: PDF, Excel, HTML and CSV with
the 15 sections (Executive Summary, Domain Information, GPO Inventory, Configuration Details, Password and
Account Security Policies, Windows Security Policies, Browser Security Policies, User and Computer
Configuration, OU Links and Inheritance, Conflicting and Duplicate Settings, Missing or Weak Security
Configurations, Risk Classification, Recommendations and Remediation, Historical Changes, Audit Trail).
A sample built from fictitious data is in `docs/samples/sample-gpo-report.pdf`.

---

## 3. Active Directory

### 3.1 Add a domain
Active Directory → Domains → *Add domain*:
* **LDAP URL** `ldaps://dc01.corp.example.com:636`. Plain `ldap://` is accepted only with StartTLS — directory
  credentials are never sent unencrypted.
* **Base DN** `DC=corp,DC=example,DC=com`.
* **Service account** — a credential of kind *user name + password*. Any domain user can read the inventory;
  do not use an administrator. Use a long random password and *Password never expires* only with compensating
  controls (it is reported in the privileged/risky reports if it is privileged).
* **Validate the DC certificate** (default). If your DCs use an internal CA, copy its PEM to
  `/opt/infrapilot/certs/` and set *CA certificate file* to `/opt/infrapilot/certs/<file>.pem`.
* **Sync every N hours** (default 6) and **Inactive after N days** (default 90).
* **Domain controller for account actions** (optional) — a Windows device; bulk actions run there.

*Test connection* binds and checks the base DN; *Sync now* reads users, computers, groups (with members), OUs
and DCs (paged, 500 per page). The worker synchronises due domains every 5 minutes.

### 3.2 What is reported
Users, groups, computers, OUs and domain controllers with properties; reports: inactive users, stale computers,
password expiry (uses `msDS-UserPasswordExpiryTimeComputed`, so fine-grained policies are honoured), account
expiry, privileged accounts (recursive membership of Domain/Enterprise/Schema Admins, Administrators, Account/
Server/Backup/Print Operators, Group Policy Creator Owners, Key Admins, DnsAdmins), Domain Admins membership,
group membership, risky accounts (password not required, reversible encryption, DES-only, no Kerberos
pre-authentication, unconstrained delegation, privileged accounts with SPNs or non-expiring passwords),
recently created/modified/disabled/deleted, and the domain password policy. All export to PDF, Excel, CSV, HTML.

Change detection: between synchronisations InfraPilot records created, deleted, enabled/disabled objects,
privileged membership added/removed and membership changes of privileged groups. Privileged changes raise an
alert. `lastLogonTimestamp` replicates with up to 14 days' delay; thresholds below 30 days are not reliable.

### 3.3 Account actions
Users tab → select accounts → *Bulk action*: disable, enable, unlock, add to / remove from group. The preview
shows warnings (already disabled, privileged account, not found). *Create jobs* creates one job per account on
the configured DC (`windows.ad.user.set_enabled`, `windows.ad.user.unlock`, `windows.ad.group.add_member` …),
so approval policies, maintenance windows and the audit trail apply. Single-account operations (create user,
reset password, create OU) are available on the DC's Manage console as before.

---

## 4. IT Audit

### 4.1 Frameworks
Built-in: **ISO/IEC 27001:2022** (Annex A controls with an IT-infrastructure component), **CIS Controls v8 /
CIS Benchmarks** (via the GPO baseline), **NIST CSF 2.0** and the **RBI Cyber Security Framework** baseline
controls with related IT Governance Master Direction (2023) expectations. Control texts are InfraPilot summaries,
not the licensed standards. You can add custom frameworks and controls (API `POST /api/compliance/frameworks`,
`/frameworks/{id}/controls`) and map controls to automated checks. For RBI, confirm which requirements apply to
your regulated activities and mark the rest *Not applicable* in each assessment.

### 4.2 Automated checks
24 checks produce **technical evidence** from InfraPilot's own data: asset inventory, software inventory,
patch status, configuration backups, off-server backup copies, GPO baseline areas (password, audit, malware,
host firewall, remote access, Windows Update, removable media), AD (dormant users, stale computers,
privileged accounts, risky accounts, domain password policy), Linux SSH hardening, firewall rule analysis,
monitoring coverage, audit-trail integrity, change control and MFA for administrators. A check returns
*Not assessed* when its data source is missing or stale — it never guesses. Simulated devices are excluded.

### 4.3 Running an assessment
IT Audit → Assessments → *New assessment*: framework, title, audit period, scope (description, optional site).
The automated checks run immediately; their full input is stored as a **system evidence file** (JSON, SHA-256)
and referenced from every control result. Non-compliant items become **findings** with severity, asset,
recommendation and a target date (critical 7 days, high 30, medium 90, low 180). Re-running checks updates
automated results and never overwrites a result an auditor recorded, and never duplicates findings.

Record a control manually by clicking it: status (compliant, partially compliant, non-compliant, not
applicable, not assessed), evidence summary, auditor notes and evidence files. Assessed controls require
evidence. *Submit for review* → another auditor *Approves* → the assessment is locked.

### 4.4 Findings
Lifecycle: **Open → Assigned → In progress → Pending verification → Closed**, or **Accepted risk** (with reason
and review date). Assigning needs an owner or department; closing and reopening need a comment. Every
transition is stored in the finding's history and the audit trail.

### 4.5 Evidence repository
Upload files up to 25 MB (PDF, images, logs, CSV/Excel, Word, JSON/XML, HTML, ZIP, EVTX, configs). The SHA-256 is
recorded at upload and **re-verified on every download** (a mismatch blocks the download and is audited).
Evidence is never deleted: it can be *withdrawn* with a reason; the file and hash remain.

### 4.6 Audit report
Assessment → PDF / Excel / CSV / HTML: title and period, scope and assets, executive summary (auditor text plus a
factual summary), control counts, critical and high findings, control-by-control results with evidence and
notes, findings detail (root cause, business impact, corrective action, owner, target date, status, risk
acceptance), evidence register with integrity status, historical comparison with earlier assessments of the same
framework, and auditor comments/approval. The report states that it does not certify compliance.
A sample is in `docs/samples/sample-audit-report-iso27001.pdf`.

---

## 5. Report Center

Reports → Report Center: Daily IT Infrastructure Health, Weekly Server Health, Monthly Infrastructure Audit,
Active Directory Security, Complete GPO, Firewall Security, Switch and Network Audit, Patch Compliance,
Privileged Account, Configuration Change, Vulnerability and Risk, Management Executive Summary. Filters (per
template): period, site, department, device type, asset, severity, AD domain, GPO domain. Formats: PDF, Excel,
CSV, HTML. Each template needs a permission (shown with a lock when you lack it). The previous operational
reports remain under *Operational reports*.

**Scheduled reports** (`reports:manage`): preset or cron schedule (UTC), format, filters and recipients. The
report runs with the **owner's permissions** (whoever last saved the schedule) and is e-mailed as an attachment
(configure SMTP under Settings → E-mail). *Run now* executes immediately.

**Historical reports**: every generated file (on-demand exports, GPO/audit/AD exports and scheduled runs) is
kept with its SHA-256 for `reports.retention_days` (default 365) and can be downloaded again by users who hold
the report's permission.

Honest data: where a data source is not set up (no AD domain, no patch scans, no firewall rule analysis) the
report says so instead of showing zeros. Third-party vulnerability feeds (CVE databases) are not integrated.

---

## 6. Navigation

The sidebar is grouped as Overview, Infrastructure (filtered views of the device inventory: Windows/Linux
servers, firewalls, switches, routers, access points), Active Directory, Group Policy, Security Operations,
Operations, IT Audit, Reports and Administration. Groups collapse; the active group always opens. Breadcrumbs
show the location; the dashboard has a security-posture row (GPO baseline score, AD hygiene, audit status).
