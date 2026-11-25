# InfraPilot — Unified IT Infrastructure Management Platform

Self-hosted web platform to inventory, monitor, configure and automate **Windows Server, Linux,
switches/routers/access points, firewalls, Proxmox/VMware and storage** — with role-based access,
change approval, maintenance windows, dry-run, verification, configuration diffs and a
tamper-evident audit trail.

**Stack:** React + TypeScript + Tailwind · FastAPI · Microsoft SQL Server 2022 · Ansible Core + ansible-runner ·
WinRM/PSRP · SSH (paramiko, Netmiko) · REST/XML vendor APIs · SNMPv3 · Docker Compose on Ubuntu 22.04/24.04.

**Day-to-day management:** an operations dashboard (health, availability, 7-day activity, backup
coverage, needs-attention list); a per-device **Manage** console where services, processes, users,
updates, ports, firewall policies, VMs and snapshots appear as tables with one-click row actions
(each still previewed, approved and audited); recurring **Schedules**; **Reports** with CSV/Excel
export; and editable approval **Policies**.

**1.1 adds** a readable **Group Policy** module (all GPOs explained in plain language, CIS/Microsoft-aligned
baseline, precedence, conflicts, history, backup/restore, 15-section reports), **Active Directory** inventory and
hygiene reports over LDAPS, an **IT audit engine** (ISO 27001:2022, CIS v8, NIST CSF 2.0, RBI) with automated
evidence, findings lifecycle and an integrity-checked evidence repository, and a **Report Center** with 12
templates in PDF/Excel/CSV/HTML and scheduled e-mail delivery. See [docs/MODULES_1.1.md](docs/MODULES_1.1.md).

## Install

```bash
tar -xzf infrapilot-1.1.1.tar.gz && cd infrapilot-1.1.1
sudo bash install.sh                     # interactive wizard; or --non-interactive --answers answers.env --yes
```

One entry point installs prerequisites, Docker, SQL Server, the API, worker and web proxy, generates
secrets and TLS, creates the database, runs migrations, creates the administrator, configures UFW,
validates every service and prints the URL. Maintenance: `infrapilot-update`, `infrapilot-backup`,
`infrapilot-restore`, `infrapilot-health-check`, `infrapilot-uninstall`. Offline: `./make-bundle.sh --offline`.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architecture, module breakdown, ERD, flows, security controls |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Requirements, ports, install (online/offline/unattended), upgrade, backup/restore, TLS |
| [docs/ADMIN_MANUAL.md](docs/ADMIN_MANUAL.md) | Users/roles, AD, MFA, credentials, approvals, monitoring, audit, operations |
| [docs/MODULES_1.1.md](docs/MODULES_1.1.md) | Group Policy, Active Directory inventory, IT audit & compliance, Report Center, new roles |
| [docs/SECURITY_HARDENING.md](docs/SECURITY_HARDENING.md) | Production hardening checklist and service-account guidance |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Architecture assessment, what 1.1 delivers, next phases |
| [docs/samples/](docs/samples/) | Sample GPO report, audit report and executive summary (fictitious data) |
| [docs/USER_MANUAL.md](docs/USER_MANUAL.md) | Day-to-day use |
| [docs/DRIVERS.md](docs/DRIVERS.md) | Per-vendor capability matrix and target prerequisites |
| [docs/API.md](docs/API.md) | REST API (also live at `/api/docs`) |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Problems and fixes |
| [docs/STATUS.md](docs/STATUS.md) | What was verified, what to verify on site, known limitations |
| [docs/schema-mssql.sql](docs/schema-mssql.sql) | Generated SQL Server DDL |

## Repository layout

```
install.sh update.sh backup.sh restore.sh uninstall.sh health-check.sh make-bundle.sh   single installer + maintenance
lib/common.sh                     shared shell helpers
deploy/                           docker-compose.yml, env.template, answers.example.env, nginx/
backend/                          FastAPI app (app/), Alembic migrations, Ansible playbooks, tests, Dockerfile
frontend/                         React/TypeScript/Tailwind UI, Vitest tests, Dockerfile (build + nginx)
tests/installer/                  installer helper tests and clean-VM end-to-end test (Multipass)
docs/                             manuals and reference
```

## Development

```bash
# backend (SQLite for local development; SQL Server in production)
cd backend && pip install -r requirements-dev.txt
export IP_DATABASE_URL=sqlite:///./dev.db IP_VAULT_MASTER_KEY=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())") \
       IP_APP_MODE=demo IP_COOKIE_SECURE=false
python -m app.cli migrate && echo 'Adm1n!Passw0rd#' | python -m app.cli create-admin --username admin
uvicorn app.main:app --reload & python -m app.worker &
pytest                                   # 206 tests

# frontend
cd frontend && npm ci && npm run dev     # proxies /api to :8000
npm test && npm run build
```

Demo mode (`IP_APP_MODE=demo`) allows clearly-marked **simulated** devices for training and demos;
production mode refuses them. Never point development or tests at real infrastructure.
