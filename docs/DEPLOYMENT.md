# Deployment Guide

## 1. Requirements

| Item | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu Server 22.04 or 24.04 LTS, x86-64 | same, dedicated VM |
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB (SQL Server alone needs 2 GB) | 8–16 GB |
| Disk | 20 GB free on `/opt` and `/var/lib/docker` | 60 GB+ (metrics, config backups, DB backups) |
| Network | inbound 443 (and 80 for redirect) from admin networks; outbound to managed devices | dedicated management VLAN |

Outbound ports the **server** needs towards managed devices (open only what you use):

| Target | Port | Protocol |
|---|---|---|
| Windows | 5986 (HTTPS, recommended) / 5985 | WinRM / PSRP |
| Linux, network CLI | 22 | SSH |
| FortiGate | 443 | REST API (add the server IP to the API admin's trusted hosts) |
| Sophos Firewall | 4444 | XML API (enable API access for the server IP) |
| Proxmox VE | 8006 | REST API |
| vCenter | 443 | vSphere Automation REST (7.0U2+) |
| SNMP devices | 161/udp | SNMPv3 (authPriv) |
| AD | 636 (LDAPS) or 389 + StartTLS | LDAP |
| SMTP | 587 / 465 / 25 | e-mail |
| Zabbix / LibreNMS | 443 | API |

Online installation also needs outbound HTTPS to `download.docker.com`, Docker Hub, `mcr.microsoft.com`,
`packages.microsoft.com`, `pypi.org`, `files.pythonhosted.org` and `registry.npmjs.org` (images are built on
the target). Use the **offline bundle** where that is not allowed.

## 2. Install (single entry point)

```bash
tar -xzf infrapilot-1.1.1.tar.gz        # or infrapilot-1.1.1-offline.tar.gz
cd infrapilot-1.1.1
sudo bash install.sh
```

The interactive wizard asks for: DNS name, HTTPS port, TLS certificate (or generates a self-signed one),
SQL Server edition (Express/Developer free; Standard/Enterprise need your product key), the initial
administrator (password can be generated), optional Active Directory (LDAPS) settings and whether to
configure UFW. It then performs 13 steps with progress output and a full log in
`/var/log/infrapilot-install-*.log`:

1. preflight (OS, architecture, CPU, RAM, disk, systemd, free ports, internet or bundle)
2. detect an existing installation → offers an in-place **upgrade/repair** (data is backed up first)
3. configuration wizard
4. prerequisites (`curl`, `openssl`, `ufw`, `jq`, …)
5. Docker Engine + Compose plugin (pinned version, from the Docker apt repository or the bundle)
6. directories, secrets (vault master key, DB passwords — random, root:10001 mode 640), TLS certificate, `.env`
7. container images (built locally, or loaded from the bundle)
8. SQL Server start, database creation, least-privilege app login, migrations (as `sa`), seed data
9. initial administrator (password passed on stdin, never on the command line)
10. start `api`, `worker`, `proxy` and wait for health checks
11. UFW (SSH, 80, HTTPS port)
12. maintenance commands `infrapilot-{update,backup,restore,health-check,uninstall}` and nightly backup cron
13. full health check, then prints the URL and first steps

### Unattended

```bash
cp deploy/answers.example.env answers.env && vi answers.env
sudo ./install.sh --non-interactive --answers answers.env --yes
```

### Offline

On a build machine with internet and Docker: `./make-bundle.sh --offline` produces
`dist/infrapilot-<ver>-offline.tar.gz` containing the prebuilt images (API, proxy, SQL Server) and
Docker Engine `.deb` packages for jammy and noble. Copy it to the target and run `install.sh` — the
installer detects `bundle/` automatically.

## 3. What gets installed

```
/opt/infrapilot/
  .env                      non-secret configuration (root:10001 640)
  docker-compose.yml        stack definition (re-written on update; local overrides re-applied)
  secrets/                  vault_key, db_password, mssql_sa_password, mssql.env, [ldap_bind_password]
  certs/                    tls.crt, tls.key, [ldap-ca.pem]
  backups/mssql/            SQL Server .bak files      backups/config/   encrypted config archives
  logs/                     install/update/backup logs
  release/                  copy of the release (scripts, sources, docs)
```

Containers: `mssql`, `api`, `worker`, `proxy` (+ one-off `tools`). Volumes: `mssql-data`, `runner-data`.

## 4. Upgrade

`sudo infrapilot-update` (or run `install.sh` from the new release). It takes a verified database
backup, builds/loads the new images, preserves `.env`, secrets and certificates, adds new settings
with defaults, runs migrations and restarts services. If anything fails it rolls back images and
compose file and prints the restore command for the pre-upgrade backup.

## 5. Backup and restore

* Nightly at 01:30: `infrapilot-backup --keep-days 14` — SQL Server `BACKUP … WITH CHECKSUM` +
  `RESTORE VERIFYONLY`, an archive of `.env`/secrets/certs, and audit-chain verification.
* Manual: `sudo infrapilot-backup`.
* **Copy `/opt/infrapilot/backups` and `/opt/infrapilot/secrets` off the server.** Without
  `secrets/vault_key` the encrypted credentials in a database backup cannot be decrypted.
* Restore: `sudo infrapilot-restore --db /opt/infrapilot/backups/mssql/<file>.bak [--config <archive>]`
  stops the app, restores, re-runs migrations, verifies the audit chain and restarts.

## 6. TLS certificate replacement

```bash
sudo cp corp.crt /opt/infrapilot/certs/tls.crt && sudo cp corp.key /opt/infrapilot/certs/tls.key
sudo chown root:101 /opt/infrapilot/certs/tls.* && sudo chmod 640 /opt/infrapilot/certs/tls.key
cd /opt/infrapilot && sudo docker compose restart proxy
```

## 7. Uninstall

`sudo infrapilot-uninstall` (keeps data and backups) or `--purge` (removes volumes and `/opt/infrapilot`
after a final backup unless `--no-backup`).
