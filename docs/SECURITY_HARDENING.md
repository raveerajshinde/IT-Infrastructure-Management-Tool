# Security Hardening Guide

Checklist for running InfraPilot in production. Items marked *(default)* are already configured by the installer.

## Host and network
* Dedicated Ubuntu 22.04/24.04 VM in a management network; only TCP 443 (and 80 for redirect) from admin
  networks. UFW rules are applied by the installer *(default)*.
* Outbound from the host only to managed devices (WinRM 5985/5986, SSH 22, HTTPS APIs, SNMP 161, LDAPS 636, SMB 445
  for backup copies) and the SMTP relay. Containers: the database network is internal-only *(default)*.
* Keep the OS patched (`unattended-upgrades`), and run `infrapilot-update` for each release.
* Replace the self-signed certificate with one from your CA (DEPLOYMENT.md §6).

## Identity and access
* Enable **Require MFA** (Settings → Security); the *platform MFA* audit check reports administrators without it.
* Use AD sign-in (LDAPS) with group-to-role mapping; keep one local break-glass Super Administrator with a
  long password stored offline.
* Grant the least role: Read-only Management User for managers, Auditor / Compliance Officer for audit staff,
  device-group scoping for regional teams.
* Keep approval policies for critical and production changes enabled *(default)*; the *change control* check
  reports gaps.

## Service accounts on managed systems
* **AD inventory:** an ordinary domain user (no admin rights), LDAPS with certificate validation.
* **GPO collection:** read access to GPOs and SYSVOL is enough; run it on a DC or GPMC server over WinRM HTTPS.
* **GPO backup/restore and AD account actions:** a separate delegated account (GPO edit rights on the specific
  GPOs; account-operator style delegation on the relevant OUs) — not Domain Admin. These operations require approval.
* **Network/firewall:** read-only API users for inventory/backup; change accounts only where changes are needed.
* Credentials are stored with AES-256-GCM envelope encryption, never returned by the API or written to logs *(default)*.

## Data protection
* Configure backup copies (Settings → Backup): SMB 3 encryption required *(default)*, encrypted configuration archive.
* Evidence and report files are stored in SQL Server (VARBINARY(MAX)); include the database in your backup
  regime (`infrapilot-backup` nightly *(default)*). Set `reports.retention_days` to your retention policy.
* Device configuration copies in *full* mode contain secrets — restrict the share/folder to administrators or
  use *masked* copies.

## Monitoring the platform itself
* Verify the audit hash chain regularly: `infrapilot-health-check --verify-audit` (also an automated audit check).
* Forward the API/worker logs (`docker compose logs`) to your SIEM; secrets are redacted *(default)*.
* Review alerts *GPO changed*, *AD privileged change* and *Integrity check FAILED* on evidence downloads.
