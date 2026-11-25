# API Reference

The REST API (190 endpoints) is documented live (OpenAPI 3) at **`https://<server>/api/docs`** (Swagger UI) and
`/api/redoc`; the machine-readable spec is `/api/openapi.json`.

## Authentication

```bash
# 1. sign in (add "totp": "123456" when MFA is enabled; a first call without it returns {"mfa_required": true})
curl -sk -c jar -H 'X-Requested-With: InfraPilot' -H 'Content-Type: application/json' \
     https://infrapilot.corp.local/api/auth/login -d '{"username":"svc-report","password":"..."}'
# 2. call the API with the session cookie; state-changing requests need the anti-CSRF header
curl -sk -b jar https://infrapilot.corp.local/api/devices?environment=production
curl -sk -b jar -H 'X-Requested-With: InfraPilot' -H 'Content-Type: application/json' \
     https://infrapilot.corp.local/api/jobs/preview \
     -d '{"operation_id":"linux.service.restart","device_ids":[12],"params":{"unit":"nginx"}}'
```

The session token may also be sent as `Authorization: Bearer <token>` by non-browser clients (the
CSRF header is then not required). Sessions expire after `IP_SESSION_TTL_MINUTES` (absolute) and
`IP_SESSION_IDLE_MINUTES` (idle). Create a dedicated user with the narrowest role for integrations.

## Conventions

* JSON in/out; timestamps are ISO-8601 UTC (`…Z`).
* Lists are paged: `?page=1&page_size=25` → `{"items": [...], "total": n, "page": 1, "page_size": 25}`.
* Errors: `{"detail": {"code": "validation_failed|forbidden|not_found|conflict|unsupported_operation|device_connection_failed|rate_limited|…", "message": "human readable", "errors": [{"field": "...", "message": "..."}]}}`.
* Rate limits: sign-in 10/min per IP (also enforced by nginx), API 600/min per user → HTTP 429.
* Permissions are enforced per endpoint and per device (device-group scoped roles).

## Operations and jobs

* `GET /api/operations` — catalogue (id, name, family, risk low|medium|critical, check_mode, JSON Schema of parameters, whether you may run it).
* `GET /api/devices/{id}` — includes the operations available for that device with `allowed` flags.
* `POST /api/devices/{id}/operations/{operation_id}/read` — run a **read-only** operation synchronously (body: parameters).
* `POST /api/jobs/preview` → change summary, targets, permission per target, approval/window requirements.
* `POST /api/jobs` `{operation_id, device_ids, params, check_mode, emergency, reason, title}` → job (`queued` / `pending_approval` / `waiting_window`).
* `GET /api/jobs/{id}` → executions with output, data, before/after state, verification, rollback hint, approval and config diffs.

Operation ids per driver are listed in `docs/DRIVERS.md`.

## Endpoint index

### Active directory

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/ad/bulk` | Bulk Action |
| `GET` | `/api/ad/changes` | List Changes |
| `GET` | `/api/ad/domains` | List Domains |
| `POST` | `/api/ad/domains` | Create Domain |
| `DELETE` | `/api/ad/domains/{did}` | Delete Domain |
| `PUT` | `/api/ad/domains/{did}` | Update Domain |
| `POST` | `/api/ad/domains/{did}/sync` | Sync Domain |
| `POST` | `/api/ad/domains/{did}/test` | Test Domain |
| `GET` | `/api/ad/objects` | List Objects |
| `GET` | `/api/ad/objects/{oid}` | Get Object |
| `GET` | `/api/ad/reports` | List Ad Reports |
| `GET` | `/api/ad/reports/{key}` | Get Ad Report |
| `GET` | `/api/ad/summary` | Ad Summary |

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Login |
| `POST` | `/api/auth/logout` | Logout |
| `GET` | `/api/auth/me` | Me |
| `POST` | `/api/auth/mfa/disable` | Mfa Disable |
| `POST` | `/api/auth/mfa/enable` | Mfa Verify |
| `POST` | `/api/auth/mfa/setup` | Mfa Setup |
| `POST` | `/api/auth/mfa/verify` | Mfa Verify |
| `POST` | `/api/auth/password` | Change Password |

### Credentials

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/credentials` | List Credentials |
| `POST` | `/api/credentials` | Create Credential |
| `DELETE` | `/api/credentials/{cred_id}` | Delete Credential |
| `PATCH` | `/api/credentials/{cred_id}` | Update Credential |

### Governance

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/approval-policies` | List Policies |
| `POST` | `/api/approval-policies` | Create Policy |
| `DELETE` | `/api/approval-policies/{pid}` | Delete Policy |
| `PUT` | `/api/approval-policies/{pid}` | Update Policy |
| `GET` | `/api/approvals` | List Approvals |
| `POST` | `/api/approvals/{aid}/decide` | Decide |
| `POST` | `/api/approvals/{aid}/decision` | Decide |
| `GET` | `/api/audit` | List Audit |
| `GET` | `/api/audit/export` | Export Audit |
| `GET` | `/api/audit/verify` | Verify Audit |
| `GET` | `/api/maintenance-windows` | List Windows |
| `POST` | `/api/maintenance-windows` | Create Window |
| `DELETE` | `/api/maintenance-windows/{wid}` | Delete Window |

### Group policy

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/gpo/baseline` | Gpo Baseline |
| `PUT` | `/api/gpo/baseline/{rule_id}/exclusion` | Gpo Baseline Exclusion |
| `POST` | `/api/gpo/collect` | Gpo Collect |
| `GET` | `/api/gpo/collections` | Gpo Collections |
| `POST` | `/api/gpo/compare` | Gpo Compare |
| `GET` | `/api/gpo/diff` | Gpo Diff |
| `GET` | `/api/gpo/domains` | Gpo Domains |
| `GET` | `/api/gpo/gpos/{guid}` | Gpo Detail |
| `GET` | `/api/gpo/history/{guid}` | Gpo History |
| `GET` | `/api/gpo/overlaps` | Gpo Overlaps |
| `GET` | `/api/gpo/overview` | Gpo Overview |
| `GET` | `/api/gpo/precedence` | Gpo Precedence |
| `GET` | `/api/gpo/report` | Gpo Report |
| `GET` | `/api/gpo/rules` | Gpo Rules |
| `POST` | `/api/gpo/upload` | Gpo Upload |

### Inventory

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/backups-diff` | Diff Backups |
| `GET` | `/api/backups/{backup_id}` | Get Backup |
| `GET` | `/api/devices` | List Devices |
| `POST` | `/api/devices` | Create Device |
| `GET` | `/api/devices-export` | Export Devices |
| `POST` | `/api/devices-import` | Import Devices |
| `GET` | `/api/devices-import/template` | Import Template |
| `DELETE` | `/api/devices/{device_id}` | Delete Device |
| `GET` | `/api/devices/{device_id}` | Get Device |
| `PUT` | `/api/devices/{device_id}` | Update Device |
| `GET` | `/api/devices/{device_id}/backups` | List Backups |
| `POST` | `/api/devices/{device_id}/test` | Test Device |
| `POST` | `/api/devices/{device_id}/tls` | Set Device Tls |
| `POST` | `/api/discovery` | Discover |
| `GET` | `/api/groups` | List Groups |
| `POST` | `/api/groups` | Create Group |
| `DELETE` | `/api/groups/{group_id}` | Delete Group |
| `PUT` | `/api/groups/{group_id}` | Update Group |
| `POST` | `/api/groups/{group_id}/members` | Group Members |
| `GET` | `/api/meta` | Meta |
| `GET` | `/api/operations` | Operations |
| `GET` | `/api/platforms` | Platforms |
| `GET` | `/api/saved-filters` | List Filters |
| `POST` | `/api/saved-filters` | Save Filter |
| `DELETE` | `/api/saved-filters/{fid}` | Delete Filter |
| `GET` | `/api/sites` | List Sites |
| `POST` | `/api/sites` | Create Site |
| `DELETE` | `/api/sites/{site_id}` | Delete Site |
| `PUT` | `/api/sites/{site_id}` | Update Site |

### It audit

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/compliance/assessments` | List Assessments |
| `POST` | `/api/compliance/assessments` | Create Assessment |
| `GET` | `/api/compliance/assessments/{aid}` | Get Assessment |
| `PUT` | `/api/compliance/assessments/{aid}` | Edit Assessment |
| `GET` | `/api/compliance/assessments/{aid}/report` | Assessment Report |
| `PUT` | `/api/compliance/assessments/{aid}/results/{control_id}` | Set Result |
| `POST` | `/api/compliance/assessments/{aid}/run` | Rerun |
| `POST` | `/api/compliance/assessments/{aid}/status` | Assessment Status |
| `GET` | `/api/compliance/checks` | List Checks |
| `GET` | `/api/compliance/checks/preview` | Preview Checks |
| `GET` | `/api/compliance/dashboard` | Dashboard |
| `GET` | `/api/compliance/evidence` | List Evidence |
| `POST` | `/api/compliance/evidence` | Upload Evidence |
| `GET` | `/api/compliance/evidence/{eid}/download` | Download Evidence |
| `POST` | `/api/compliance/evidence/{eid}/withdraw` | Withdraw Evidence |
| `GET` | `/api/compliance/findings` | List Findings |
| `POST` | `/api/compliance/findings` | Create Finding |
| `GET` | `/api/compliance/findings/{fid}` | Get Finding |
| `PUT` | `/api/compliance/findings/{fid}` | Edit Finding |
| `POST` | `/api/compliance/findings/{fid}/status` | Move Finding |
| `GET` | `/api/compliance/frameworks` | Frameworks |
| `POST` | `/api/compliance/frameworks` | Create Framework |
| `GET` | `/api/compliance/frameworks/{fid}/controls` | Controls |
| `POST` | `/api/compliance/frameworks/{fid}/controls` | Add Control |

### Management

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/reports` | List Reports |
| `GET` | `/api/reports/{key}` | Get Report |
| `GET` | `/api/schedules` | List Schedules |
| `POST` | `/api/schedules` | Create Schedule |
| `GET` | `/api/schedules/preview` | Preview Cron |
| `DELETE` | `/api/schedules/{sid}` | Delete Schedule |
| `PUT` | `/api/schedules/{sid}` | Update Schedule |
| `POST` | `/api/schedules/{sid}/run` | Run Schedule Now |

### Monitoring

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/alert-rules` | List Rules |
| `POST` | `/api/alert-rules` | Create Rule |
| `DELETE` | `/api/alert-rules/{rid}` | Delete Rule |
| `PUT` | `/api/alert-rules/{rid}` | Update Rule |
| `GET` | `/api/alerts` | List Alerts |
| `POST` | `/api/alerts/{aid}/{action}` | Alert Action |
| `GET` | `/api/backup-folder` | Backup Folder Status |
| `POST` | `/api/backup-folder/export-configs` | Backup Folder Export |
| `POST` | `/api/backup-folder/test` | Backup Folder Test |
| `GET` | `/api/backup-storage` | Backup Storage Status |
| `POST` | `/api/backup-storage/export-configs` | Backup Storage Export |
| `POST` | `/api/backup-storage/test` | Backup Storage Test |
| `GET` | `/api/branding` | Get Branding |
| `GET` | `/api/dashboard` | Dashboard |
| `GET` | `/api/devices/{device_id}/metrics` | Device Metrics |
| `GET` | `/api/devices/{device_id}/metrics/latest` | Latest Metrics |
| `GET` | `/api/integrations` | List Integrations |
| `POST` | `/api/integrations` | Create Integration |
| `DELETE` | `/api/integrations/{iid}` | Delete Integration |
| `POST` | `/api/integrations/{iid}/sync` | Sync Integration |
| `POST` | `/api/integrations/{iid}/test` | Sync Integration |
| `GET` | `/api/notifications` | List Notifications |
| `POST` | `/api/notifications/read` | Read All |
| `POST` | `/api/notifications/read-all` | Read All |
| `GET` | `/api/search` | Search |
| `GET` | `/api/settings` | Get Settings All |
| `PUT` | `/api/settings` | Put Settings |
| `POST` | `/api/settings/test-email` | Test Email |
| `POST` | `/api/settings/test-ldap` | Test Ldap |
| `GET` | `/api/setup/status` | Setup Status |
| `GET` | `/api/system/diagnostics` | Diagnostics Info |
| `DELETE` | `/api/system/diagnostics/errors` | Diagnostics Clear |

### Operations

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/approved-commands` | Approved Commands |
| `GET` | `/api/devices/{device_id}/operations` | Device Operations |
| `POST` | `/api/devices/{device_id}/operations/{operation_id}/read` | Run Read |
| `GET` | `/api/jobs` | List Jobs |
| `POST` | `/api/jobs` | Submit Job |
| `POST` | `/api/jobs/preview` | Preview |
| `GET` | `/api/jobs/{job_id}` | Get Job |
| `POST` | `/api/jobs/{job_id}/cancel` | Cancel Job |
| `GET` | `/api/playbooks` | List Playbooks |
| `GET` | `/api/templates` | List Templates |
| `POST` | `/api/templates` | Create Template |
| `DELETE` | `/api/templates/{tid}` | Delete Template |
| `POST` | `/api/templates/{tid}/run` | Run Template |

### Report center

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/report-center/reports/{key}` | Generate |
| `GET` | `/api/report-center/schedules` | List Schedules |
| `POST` | `/api/report-center/schedules` | Create Schedule |
| `DELETE` | `/api/report-center/schedules/{sid}` | Delete Schedule |
| `PUT` | `/api/report-center/schedules/{sid}` | Update Schedule |
| `POST` | `/api/report-center/schedules/{sid}/run` | Run Schedule Now |
| `GET` | `/api/report-center/templates` | Templates |
| `GET` | `/api/report-runs` | List Runs |
| `GET` | `/api/report-runs/{rid}/download` | Download Run |

### Scripts

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/scripts` | List Scripts |
| `POST` | `/api/scripts` | Create Script |
| `GET` | `/api/scripts/meta` | Scripts Meta |
| `GET` | `/api/scripts/{sid}` | Get Script |
| `PUT` | `/api/scripts/{sid}` | Update Script |
| `POST` | `/api/scripts/{sid}/preview` | Preview Script |
| `POST` | `/api/scripts/{sid}/retire` | Retire Script |
| `POST` | `/api/scripts/{sid}/review` | Review Script |
| `POST` | `/api/scripts/{sid}/run` | Run Script |
| `GET` | `/api/scripts/{sid}/runs` | Script Runs |

### System

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health |
| `GET` | `/api/readyz` | Readyz |

### Users

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/permissions` | List Permissions |
| `GET` | `/api/roles` | List Roles |
| `POST` | `/api/roles` | Create Role |
| `PUT` | `/api/roles/{role_id}` | Update Role |
| `GET` | `/api/users` | List Users |
| `POST` | `/api/users` | Create User |
| `PATCH` | `/api/users/{user_id}` | Update User |
| `POST` | `/api/users/{user_id}/reset-mfa` | Reset Mfa |
| `POST` | `/api/users/{user_id}/reset-password` | Reset Password |
| `POST` | `/api/users/{user_id}/unlock` | Unlock User |
