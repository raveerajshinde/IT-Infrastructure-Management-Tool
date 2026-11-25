# Troubleshooting Guide

Start with `sudo infrapilot-health-check` — it checks every container, API readiness (database,
vault, worker heartbeat), the web UI, certificate expiry, disk space and (with `--verify-audit`)
the audit chain. Logs: `cd /opt/infrapilot && sudo docker compose logs --tail 200 <service>`.
All application logs are JSON with secrets redacted.

## Installation

| Symptom | Cause / fix |
|---|---|
| "No internet access to download.docker.com" | Proxy/firewall. Allow the hosts in DEPLOYMENT §1 or use the offline bundle. |
| "Port 443 is already in use" | Another web server is running; stop it or choose another HTTPS port in the wizard. |
| SQL Server not healthy within 420 s | Usually RAM (< 2 GB available) or disk. `docker compose logs mssql`. |
| "Could not create the administrator" | Password policy: 12+ characters, 3 of upper/lower/digit/symbol, not containing the username. Re-run the installer — completed steps are skipped. |
| `open sysctl net.ipv4.ip_unprivileged_port_start … permission denied` | Docker inside an LXC container (e.g. Proxmox CT) after the containerd CVE-2025-52881 fix. Use a full VM (recommended), or on Proxmox enable nesting + keyctl and upgrade the host to VE 9.1+. Evaluation-only workaround inside the CT: `apt-get install --allow-downgrades containerd.io=1.7.28-1~ubuntu.22.04~jammy && apt-mark hold containerd.io`. |
| Installer stopped half-way | Fix the reported problem and run `sudo ./install.sh` again; it is idempotent. |

## Sign-in

| Symptom | Fix |
|---|---|
| "Account is temporarily locked" | Wait 15 min or Users → Unlock. Break-glass: `reset-admin-password` (ADMIN_MANUAL §9). |
| AD users cannot sign in | Settings → Active Directory → Test bind. Check the CA file, the bind account, and that the user is in a **mapped group** (unmapped users are denied unless a default role is set). |
| MFA codes rejected | The phone's clock must be accurate (±30 s). An admin can reset MFA for the user. |
| Signed out repeatedly | Idle timeout (`IP_SESSION_IDLE_MINUTES`); the browser must accept cookies for the site; use HTTPS (cookies are `Secure`). |

## Device connectivity (Test connectivity shows the failing layer)

| Layer | Typical cause |
|---|---|
| ICMP fails, TCP OK | ICMP filtered — harmless; availability uses the TCP fallback. |
| TCP port unreachable | Firewall between server and device, wrong port, service disabled (WinRM, SSH, API). |
| WinRM: 401 / auth error | Wrong account or transport. Kerberos needs DNS names and time sync; NTLM over HTTP is blocked by default on servers — use HTTPS (5986). |
| WinRM: certificate verify failed | Install the issuing CA in the platform trust store, or (lab only) untick "Verify TLS". |
| SSH: host key rejected | The device key changed. If expected, remove its line from the `known_hosts` file in the `runner-data` volume. |
| "needs passwordless sudo" | Grant the service account `NOPASSWD` for the required commands. |
| FortiGate 401/403 | Token invalid, or this server is not in the API admin's trusted hosts. |
| Sophos "login failed" | Enable API access and allow the server IP (Administration → API). |
| Operation says `unsupported` | That vendor/driver does not provide it, or a Windows module (RSAT AD/DNS/DHCP/GroupPolicy, IIS) is missing on the target. Nothing was changed. See `docs/DRIVERS.md`. |

## Jobs

| Symptom | Fix |
|---|---|
| Stays `queued` | Worker down: `docker compose ps worker`, `docker compose logs worker`. |
| Stays `pending_approval` | Needs an approver other than the requester with `approvals:decide` for those devices. Expires after `approval.expiry_hours`. |
| Stays `waiting_window` | Policy requires a maintenance window for those devices; create one under Approvals. |
| `failed` with "Worker interrupted" | The worker restarted mid-job. Changes are never re-run automatically — check the device state, then re-submit. |
| Timeout | Raise `IP_OPERATION_TIMEOUT_SECONDS` / `IP_DEFAULT_JOB_TIMEOUT_SECONDS` in `.env` for slow devices. |

## Monitoring / e-mail

* No metrics: the device needs monitoring enabled and a credential (or SNMPv3 credential); see the last error on the device page.
* E-mail not sent: Settings → E-mail → Send test shows the SMTP error. Port 465 uses implicit TLS, 587 STARTTLS.

## Database / backup

* `infrapilot-backup` fails at VERIFYONLY: the backup file is corrupt — check disk space and SQL Server logs.
* Audit verification failed: someone modified the database directly. Preserve the database and backups for investigation and compare with the last verified backup.
* Lost `secrets/vault_key`: stored credentials cannot be decrypted; restore the key from your secret backup or re-enter all credentials.
* Connectivity test fails with `CERTIFICATE_VERIFY_FAILED ... self-signed certificate` (Sophos, FortiGate, Proxmox, vCenter, WinRM over HTTPS): the device's certificate is not trusted by the InfraPilot host. Install the device's CA on the host, or click *Skip certificate verification and retest* under the failed test (per device, audited; revert in Edit)
* A page shows *Unexpected server error (reference XXXX)*: open **Settings → Diagnostics** (administrators). It lists recent server errors with the cause and a redacted stack trace, and **Run self-check** calls every main API endpoint to show which one fails. **Copy report** puts everything on the clipboard for support. Administrators also see the cause directly in the error message.
* After an upgrade the UI still looks old (e.g. no Settings → Branding): check the version at the bottom of the sidebar and in Settings → Diagnostics. If it is not the new version, run `sudo ./install.sh` (or `sudo ./update.sh`) from the **new** package folder; the final line prints the version the running API reports. Then reload the browser with Ctrl+F5.
* `Permission denied` when starting `install.sh`/`update.sh`: the executable bit was lost while copying the package (common with WinSCP or downloads via Windows). Run `sudo bash install.sh` (or `chmod +x *.sh` first). From 1.0.1 the installer calls its helper scripts through `bash` and repairs the permissions itself.
* Windows server without a WinRM certificate: edit the device and choose *WinRM protocol → HTTP (port 5985)*. On the server, `Enable-PSRemoting -Force` (or `winrm quickconfig`) creates the HTTP listener and firewall rule. Use a credential with Negotiate/NTLM/Kerberos authentication; Basic is refused over HTTP. For a local (non-domain) administrator account you may also need `Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System LocalAccountTokenFilterPolicy 1` on the server.
* Backup storage *Test connection* fails: the message names the cause — wrong user/password/domain (`LOGON_FAILURE`), share name wrong (`BAD_NETWORK_NAME`), missing *Modify* permission (`ACCESS_DENIED`), no route to TCP 445 (firewall/DNS), or an old NAS without SMB 3 encryption (untick *Require SMB 3 encryption* only on a trusted network).
* A change was submitted but never ran — open the job; the yellow/red box says why:
  * *Waiting for approval*: someone other than the requester with the "Approve or reject changes" permission must approve it under **Approvals**. You can never approve your own change. From 1.0.7 a change that nobody else could approve is refused at submission with this explanation. Fix: give a second person an approver role (e.g. Infrastructure Administrator), or adjust the policy in Approvals → Policies (e.g. switch off "Production changes need approval" or add a maintenance window that pre-approves medium-risk changes).
  * *Waiting for a maintenance window*: a policy (by default: production firewall changes) only allows it inside a window; create one under Approvals → Maintenance windows.
  * *Not running: the job worker is down*: run `sudo infrapilot-health-check`; restart with `sudo docker compose --project-directory /opt/infrapilot -f /opt/infrapilot/docker-compose.yml up -d worker` and check `... logs worker --tail 80`.
* `Connection is busy with results for another command` (SQL Server): fixed in 1.0.8 — connections now use MARS and the code reads each result fully before running the next query. Upgrade to 1.0.8 or later.
