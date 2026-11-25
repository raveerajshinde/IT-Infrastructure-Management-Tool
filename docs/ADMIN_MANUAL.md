# Administrator Manual

## 1. First sign-in

1. Open the URL printed by the installer and sign in with the initial administrator.
2. Enable two-factor authentication: **Settings → My account → Set up authenticator**.
3. The **onboarding wizard** (Dashboard → Start onboarding) sets the organization name and MFA policy,
   stores a first credential, registers a device and tests connectivity.
4. Configure **Settings → E-mail** (SMTP) and send a test message; configure **Settings → Active Directory**
   if users should sign in with AD accounts.

## 2. Users, roles and permissions

Built-in roles: Super Administrator, Infrastructure Administrator, Windows Server Administrator,
Linux Server Administrator, Network Administrator, Firewall Administrator, IT Support Engineer,
Auditor / Read Only. Built-in roles cannot be edited; create custom roles from the permission list
(`devices:read`, `windows:change`, `firewall:change`, `approvals:decide`, `changes:emergency`, …).

* A role assignment can be **global** or **scoped to a device group**: a Linux admin scoped to
  "Web servers" sees and changes only those devices.
* Operation permissions are `<module>:read` for read-only operations and `<module>:change` for
  changes (modules: windows, linux, network, firewall, virtualization).
* The last active global Super Administrator cannot be disabled or demoted.
* User actions: disable, unlock (after lockout), reset password (forces change at next sign-in and
  revokes sessions), reset MFA.

## 3. Active Directory (LDAPS)

> This section covers **signing in** with AD accounts. The Active Directory *inventory and reports* module,
> Group Policy reporting, IT audit and the Report Center are described in [MODULES_1.1.md](MODULES_1.1.md).


Settings → Active Directory: server URL (`ldaps://dc01.corp.local:636`, or `ldap://…:389` with
StartTLS), base DN, service account DN and password (stored in the vault), user filter, and the
**group → role mapping** (`CN=IT-Network,OU=Groups,DC=corp,DC=local = Network Administrator`).

* Users in no mapped group are **denied** unless a default role is selected.
* Mapped roles are re-synchronised at each sign-in; group-scoped roles you assign manually are kept.
* The domain CA must be trusted: place it at `/opt/infrapilot/certs/ldap-ca.pem` (the installer can do this).
* Use **Test bind** to validate. Local accounts (e.g. the break-glass admin) keep working if AD is down.

## 4. Credentials

**Windows servers: WinRM over HTTP or HTTPS.** When adding a Windows server choose the *WinRM
protocol* on the device form:
* **HTTP (port 5985)** — the listener Windows enables with `winrm quickconfig` / `Enable-PSRemoting`;
  no certificate needed. With Negotiate (default), NTLM, Kerberos or CredSSP authentication every
  message is encrypted by the authentication protocol, so commands, output and passwords are not
  sent in clear text. Basic authentication is refused over HTTP.
* **HTTPS (port 5986)** — needs a certificate bound to a WinRM HTTPS listener; if it is self-signed,
  see below.
The device port decides the protocol (5985 = HTTP, anything else = HTTPS). A credential can force
one or the other (*WinRM protocol: Always HTTPS / Always HTTP*), which overrides the port; the
connectivity test reports which protocol was used.

**Self-signed certificates (firewalls, hypervisors, WinRM over HTTPS).** If a connectivity test
fails with `CERTIFICATE_VERIFY_FAILED`, either install the device's CA certificate on the InfraPilot
host (preferred), or skip certificate verification for that one device: use the button shown under
the failed test, or Edit → untick *Verify TLS certificate*. The connection stays encrypted but the
device's identity is not checked, so only do this on a trusted management network. The change is
audited (`device.tls_verification`) and shown on the device's Overview.


Credentials → New. Kinds: username+password (SSH/CLI/Sophos/vCenter; optional Cisco enable secret),
Windows WinRM (authentication negotiate/kerberos/ntlm/credssp, HTTPS on/off), SSH private key
(host-key policy: trust-on-first-use or reject unknown), API token (FortiGate, Proxmox
`user@realm!tokenid`, Zabbix/LibreNMS), SNMPv3 authPriv. Secrets are write-only: they can be rotated
but never displayed. Deleting a credential that is in use is blocked; deletion destroys the
encrypted material.

Target preparation (least privilege):
* **Windows**: WinRM over HTTPS (`winrm quickconfig -transport:https` with a certificate), a service account
  in the groups required for the operations you use; RSAT modules (AD, DNS, DHCP, GroupPolicy) on the
  target or a management server for directory operations.
* **Linux**: a service account with key authentication and `NOPASSWD` sudo for the commands you allow
  (or use root only where policy permits).
* **Network**: SSH enabled, a privilege-15/manager account (Cisco: enable secret if needed).
* **FortiGate**: REST API admin with a profile limited to what you need, trusted host = this server.
* **Sophos**: Administration → API: enable, allow this server's IP.
* **Proxmox**: API token with the minimal privileges (e.g. `PVEAuditor` + `VM.PowerMgmt`).

## 5. Change control

* **Approval policies** (Approvals → **Policies**, defaults seeded): each policy matches a risk
  (medium/critical/any), platform and environment and requires approval and/or a maintenance window.
  Defaults: critical changes always need approval; production changes need approval (also toggled in
  Settings → General); production firewall changes also need a maintenance window. Policies can be
  created, edited, switched off and deleted (requires `approvals:manage`, audited). The last enabled
  policy requiring approval for critical changes cannot be deleted — disable it explicitly if you
  really mean to.
* **Schedules** (Operations → Schedules): recurring jobs run as their owner, so RBAC and approval
  policies apply to every run. Users with `automation:run` manage their own schedules;
  `automation:manage` can edit or delete anyone's (editing transfers ownership to the editor). Cron is
  evaluated in UTC; runs must be at least 5 minutes apart. Operations with secret parameters cannot be
  scheduled. The worker launches due runs every ~15 s; a schedule whose owner is disabled or lacks
  permission is paused and shows the reason.
* **Maintenance windows** (Approvals → Maintenance windows): time range, optional device group;
  "auto-approve medium-risk changes inside this window" lets pre-agreed routine changes run without
  a separate approval (critical changes still need one). Jobs approved outside a required window wait
  (`waiting_window`) and start automatically when one opens.
* **Segregation of duties**: a requester can never approve their own change.
* **Emergency changes** require `changes:emergency` and a justification, run immediately and create a
  post-change review item that an approver must accept or flag.
* **Approval expiry**: pending requests expire after `approval.expiry_hours` (default 72 h).

## 5b. Backup storage on a network share
Settings → **Backup storage** copies backups to an SMB share (Windows file server or NAS):

| On the share | Contents | When |
|---|---|---|
| `database\infrapilot_<label>_<time>.bak` | SQL Server backup (stored secrets inside stay vault-encrypted) | right after the nightly backup (01:30) or `sudo infrapilot-backup` |
| `config\infrapilot_config_<label>_<time>.tar.gz.enc` | `.env`, compose file, secrets incl. the vault key, certificates — **always encrypted** with the backup passphrase | same |
| `SHA256SUMS-<time>` | checksums of the uploaded files | same |
| `devices\<hostname>\<time>_<kind>.cfg` | device configuration backups with secrets masked | hourly, or *Copy device configs now* |

Setup: create a share and a dedicated account with *Modify* permission on the target folder; enter the
share path (`\\fileserver\backups\infrapilot`), account, optional domain, password and a backup
encryption passphrase (min. 12 characters — keep it in your password manager); Save; **Test connection**
(creates the folders, writes, reads back and deletes a test file). The InfraPilot server must reach the
file server on TCP 445. SMB 3 encryption in transit is required by default.

Retention deletes only files with the InfraPilot names above that are older than the configured number
of days; other files on the share are never touched. Upload results and errors appear on the page
under *Status* and in the audit log (`backup.offsite_upload`, `backup.offsite_test`). A failed upload
never fails the local backup.

Restore a device from the share: open the full copy in `devices\\<hostname>\\` and paste/upload it with the vendor's usual restore procedure (e.g. `copy tftp: startup-config` on Cisco, *System → Config → Restore* on FortiGate/Sophos). Full copies contain the device's passwords, keys and SNMP communities, so limit share access to administrators.

Restore InfraPilot itself from the share: copy the `.bak` and `.tar.gz.enc` back to the server, write the passphrase
to a root-only file, then
`sudo infrapilot-restore --db FILE.bak --config FILE.tar.gz.enc --passphrase-file PASSFILE`.
The archive can also be decrypted by hand:
`openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in FILE.tar.gz.enc -out FILE.tar.gz`.

## 5c. Device backups to a folder on the server

Settings → Backup → **Folder on the server** writes every switch, router and firewall configuration
backup into a folder you choose, about a minute after it is taken (scheduled or manual backups).

1. Pick or mount the folder on the InfraPilot host. It must be inside `/srv/infrapilot-exports`
   (created by the installer), `/mnt` or `/media`. The containers see these at the same path, so the
   path you type is the path on the host.
   * Local disk: `/srv/infrapilot-exports/device-backups`
   * USB disk: `/media/usb1/infrapilot`
   * NAS / Windows share mounted on the host, e.g. in `/etc/fstab`:
     `//fileserver/netbackups /mnt/nas cifs credentials=/root/.nascred,uid=10001,gid=10001,vers=3.0,seal 0 0`
     then use `/mnt/nas/infrapilot`.
2. Make it writable by the InfraPilot user (uid 10001): `sudo mkdir -p FOLDER && sudo chown -R 10001:10001 FOLDER`.
3. Tick **Copy device backups to a folder**, enter the folder, choose Full (restorable) or Masked copies,
   optionally a retention in days (0 = keep everything), and **Save**. Use **Test folder** to check access.

Layout: `FOLDER/<hostname>/<YYYYmmdd-HHMMSS>_<kind>.cfg` (one per changed configuration) plus
`FOLDER/<hostname>/latest_<kind>.cfg` (always the newest; can be switched off). Retention only deletes
the dated InfraPilot files; nothing else in the folder is touched. The folder and the SMB share options
can be used at the same time. Use **Copy all again** after changing Full/Masked to rewrite existing files.
The schedule itself is Settings → General → "Scheduled config backups every N hours".

## 5a. Branding
Settings → **Branding** (requires `settings:manage`): product name, organisation, sign-in tagline,
dashboard title, brand colour (buttons, links, charts — previewed live) and a logo (PNG/JPEG/WebP/SVG,
under 300 KB, stored in the database and shown only as an image). A sign-in notice can show an
acceptable-use statement or helpdesk contact. Branding is served by the public `/api/branding`
endpoint so the sign-in page uses it; changes are audited (logos as size and fingerprint only).

## 6. Monitoring and alerting

Alerts → Rules: metric (availability, CPU, memory, disk, latency, uptime, load), operator, threshold,
severity, device group, notification and escalation e-mails, escalation delay. Defaults: device
unreachable (critical), CPU/memory > 90 %, disk > 85 % (warning) and > 95 % (critical). Alerts
de-duplicate per rule and device, auto-resolve when the condition clears, can be acknowledged or
resolved, and escalate by e-mail when unacknowledged.

Integrations: Zabbix (API token, 5.4+) and LibreNMS (API token). Active problems are imported as
alerts every 5 minutes and resolved when they clear in the source system.

## 7. Configuration backups

Settings → General → "Scheduled config backups every N hours" (default 24) queues read-only backup
jobs for all switches, routers and firewalls with credentials. Backups are de-duplicated (unchanged
configs are not stored twice). Device → Config backups lets you view (secrets masked) and compare
any two versions. Every configuration change stores before/after backups and the diff on the job.

## 8. Audit

Audit log: filter by action, actor, target, result and time; export CSV; **Verify integrity**
recomputes the SHA-256 chain. Records cover sign-ins (including failures and lockouts), every change
request, approval decision, execution result per device, settings change, credential operation,
export and configuration view. Records cannot be edited or deleted (database trigger + DENY).

## 9. Platform operations

| Task | Command |
|---|---|
| Health check | `sudo infrapilot-health-check [--verify-audit]` |
| Backup now | `sudo infrapilot-backup` |
| Restore | `sudo infrapilot-restore --db <file.bak>` |
| Upgrade | `sudo infrapilot-update` |
| Logs | `cd /opt/infrapilot && sudo docker compose logs -f api worker` |
| Reset a local admin password (break-glass) | `printf '%s\n' 'N3w!Passw0rd#' \| sudo docker compose --profile tools run --rm -T tools python -m app.cli reset-admin-password --username admin` |
| Demo mode | set `IP_APP_MODE=demo` in `.env`, `docker compose up -d` — allows clearly-marked simulated devices; never use in production |

Environment settings (`/opt/infrapilot/.env`): session lifetime and idle timeout, lockout threshold,
rate limits, worker concurrency, monitoring interval, job and operation timeouts. Restart with
`docker compose up -d` after changes.
