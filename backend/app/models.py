"""SQLAlchemy ORM models (normalized schema targeting Microsoft SQL Server).

Conventions
* Integer identity PKs; BigInteger for high-volume tables (audit, metrics).
* All timestamps are naive UTC (DATETIME2 on SQL Server).
* JSON columns map to NVARCHAR(MAX) on SQL Server.
* No ON DELETE CASCADE chains (SQL Server forbids multiple cascade paths); deletes are
  handled in the service layer, devices are soft-deleted.
* Secrets are never stored here in plaintext: see VaultSecret (AES-256-GCM envelope).
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, LargeBinary,
    String, UnicodeText, UniqueConstraint,
)
from sqlalchemy.dialects.mssql import VARBINARY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.core.timeutil import utcnow


# ---------------------------------------------------------------- identity / RBAC
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    email: Mapped[str | None] = mapped_column(String(254))
    auth_source: Mapped[str] = mapped_column(String(16), default="local")  # local | ldap
    password_hash: Mapped[str | None] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret_id: Mapped[int | None] = mapped_column(ForeignKey("vault_secrets.id"))
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    role_assignments: Mapped[list["UserRole"]] = relationship(back_populates="user", lazy="selectin")


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    permissions: Mapped[list["Permission"]] = relationship(secondary="role_permissions", lazy="selectin")


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(String(300), default="")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), primary_key=True)


class UserRole(Base):
    """Role assignment; device_group_id=None means global scope."""
    __tablename__ = "user_roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    device_group_id: Mapped[int | None] = mapped_column(ForeignKey("device_groups.id"))
    user: Mapped[User] = relationship(back_populates="role_assignments")
    role: Mapped[Role] = relationship(lazy="selectin")
    __table_args__ = (UniqueConstraint("user_id", "role_id", "device_group_id", name="uq_user_role_scope"),)


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


# ---------------------------------------------------------------- vault / credentials
class VaultSecret(Base):
    __tablename__ = "vault_secrets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    purpose: Mapped[str] = mapped_column(String(100))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(16))
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary(64))
    key_nonce: Mapped[bytes] = mapped_column(LargeBinary(16))
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime)


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    kind: Mapped[str] = mapped_column(String(32))  # password | ssh_key | api_token | snmpv3 | winrm
    username: Mapped[str | None] = mapped_column(String(200))
    secret_id: Mapped[int | None] = mapped_column(ForeignKey("vault_secrets.id"))
    extra: Mapped[dict] = mapped_column(JSON, default=dict)  # non-secret params (auth proto, domain, transport)
    description: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


# ---------------------------------------------------------------- inventory
class Site(Base):
    __tablename__ = "sites"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    kind: Mapped[str] = mapped_column(String(20), default="datacenter")  # datacenter | branch | cloud
    address: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DeviceGroup(Base):
    __tablename__ = "device_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DeviceGroupMember(Base):
    __tablename__ = "device_group_members"
    group_id: Mapped[int] = mapped_column(ForeignKey("device_groups.id"), primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), primary_key=True)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    device_type: Mapped[str] = mapped_column(String(32), index=True)
    platform: Mapped[str] = mapped_column(String(48))  # driver key
    os_name: Mapped[str] = mapped_column(String(120), default="")
    os_version: Mapped[str] = mapped_column(String(120), default="")
    vendor: Mapped[str] = mapped_column(String(120), default="")
    model: Mapped[str] = mapped_column(String(120), default="")
    firmware: Mapped[str] = mapped_column(String(120), default="")
    serial_number: Mapped[str] = mapped_column(String(120), default="")
    owner: Mapped[str] = mapped_column(String(150), default="")
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id"))
    department: Mapped[str] = mapped_column(String(120), default="")
    location: Mapped[str] = mapped_column(String(200), default="")
    environment: Mapped[str] = mapped_column(String(20), default="production", index=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    port: Mapped[int | None] = mapped_column(Integer)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id"))
    snmp_credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id"))
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default="unknown")  # unknown|up|down|degraded
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_error: Mapped[str | None] = mapped_column(String(1000))
    notes: Mapped[str] = mapped_column(UnicodeText, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)

    site: Mapped[Site | None] = relationship(lazy="joined")
    __table_args__ = (Index("ix_devices_type_env", "device_type", "environment"),)


class SavedFilter(Base):
    __tablename__ = "saved_filters"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(150))
    module: Mapped[str] = mapped_column(String(50), default="devices")
    filter: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Integration(Base):
    __tablename__ = "integrations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    kind: Mapped[str] = mapped_column(String(32))  # zabbix | librenms | veeam | pbs
    base_url: Mapped[str] = mapped_column(String(500))
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id"))
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_test_message: Mapped[str | None] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ---------------------------------------------------------------- automation
class JobTemplate(Base):
    __tablename__ = "job_templates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    kind: Mapped[str] = mapped_column(String(16))  # operation | playbook
    category: Mapped[str] = mapped_column(String(32))  # windows | linux | network | firewall | virtualization
    operation_id: Mapped[str | None] = mapped_column(String(100))
    playbook: Mapped[str | None] = mapped_column(String(200))
    default_params: Mapped[dict] = mapped_column(JSON, default=dict)
    param_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    risk: Mapped[str] = mapped_column(String(16), default="change")
    supports_check_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(16), default="operation")  # operation | playbook
    template_id: Mapped[int | None] = mapped_column(ForeignKey("job_templates.id"))
    operation_id: Mapped[str | None] = mapped_column(String(100))
    playbook: Mapped[str | None] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(32), default="")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    change_summary: Mapped[str] = mapped_column(UnicodeText, default="")
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    check_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    risk: Mapped[str] = mapped_column(String(16), default="change")
    is_emergency: Mapped[bool] = mapped_column(Boolean, default=False)
    requires_window: Mapped[bool] = mapped_column(Boolean, default=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=900)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    worker_id: Mapped[str | None] = mapped_column(String(100))
    summary: Mapped[str | None] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    queued_at: Mapped[datetime | None] = mapped_column(DateTime)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)

    executions: Mapped[list["JobExecution"]] = relationship(back_populates="job", lazy="selectin", order_by="JobExecution.id")


class JobExecution(Base):
    """One execution of a job against one device."""
    __tablename__ = "job_executions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    output: Mapped[str] = mapped_column(UnicodeText, default="")
    error: Mapped[str | None] = mapped_column(UnicodeText)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    before_state: Mapped[str | None] = mapped_column(UnicodeText)
    after_state: Mapped[str | None] = mapped_column(UnicodeText)
    verification: Mapped[str | None] = mapped_column(UnicodeText)
    rollback_hint: Mapped[str | None] = mapped_column(UnicodeText)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    job: Mapped[Job] = relationship(back_populates="executions")


class Script(Base):
    """Library script: PowerShell (Windows), shell (Linux), CLI lines (switches) or a FortiGate CLI script.

    A script can only run once someone other than its last editor has approved exactly this content
    (approved_sha256). Editing the body or parameters returns it to 'pending'.
    """
    __tablename__ = "scripts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    target: Mapped[str] = mapped_column(String(20))  # windows | linux | network | fortigate
    mode: Mapped[str] = mapped_column(String(10), default="change")  # change | read (network: config vs show)
    risk: Mapped[str] = mapped_column(String(10), default="change")  # read | change | critical
    body: Mapped[str] = mapped_column(UnicodeText)
    params: Mapped[list] = mapped_column(JSON, default=list)  # [{name,label,type,required,default,choices,max_length}]
    run_as_root: Mapped[bool] = mapped_column(Boolean, default=False)  # linux: sudo
    save_config: Mapped[bool] = mapped_column(Boolean, default=False)  # network: write running -> startup afterwards
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    version: Mapped[int] = mapped_column(Integer, default=1)
    sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(12), default="pending")  # pending | approved | rejected | retired
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    approved_sha256: Mapped[str | None] = mapped_column(String(64))
    review_comment: Mapped[str] = mapped_column(String(1000), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class JobSchedule(Base):
    """A recurring job. Each run is created as the schedule owner, so RBAC, approval policies,
    maintenance windows and audit apply exactly as if that user had started it by hand."""
    __tablename__ = "job_schedules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    description: Mapped[str] = mapped_column(String(1000), default="")
    kind: Mapped[str] = mapped_column(String(16), default="operation")  # operation | playbook
    operation_id: Mapped[str | None] = mapped_column(String(100))
    template_id: Mapped[int | None] = mapped_column(ForeignKey("job_templates.id"))
    device_ids: Mapped[list] = mapped_column(JSON, default=list)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    check_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    cron: Mapped[str] = mapped_column(String(100))  # 5-field cron, evaluated in UTC
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_job_id: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(String(1000))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# ---------------------------------------------------------------- governance
class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), index=True)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    kind: Mapped[str] = mapped_column(String(16), default="pre")  # pre | emergency_review
    reason: Mapped[str] = mapped_column(String(2000), default="")
    decided_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime)
    decision_comment: Mapped[str | None] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ApprovalPolicy(Base):
    __tablename__ = "approval_policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    risk: Mapped[str | None] = mapped_column(String(16))  # read|change|critical|None(any)
    category: Mapped[str | None] = mapped_column(String(32))
    environment: Mapped[str | None] = mapped_column(String(20))
    require_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    require_maintenance_window: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150))
    start_at: Mapped[datetime] = mapped_column(DateTime)
    end_at: Mapped[datetime] = mapped_column(DateTime)
    environment: Mapped[str | None] = mapped_column(String(20))
    device_group_id: Mapped[int | None] = mapped_column(ForeignKey("device_groups.id"))
    auto_approve_change: Mapped[bool] = mapped_column(Boolean, default=False)  # medium-risk changes inside the window skip pre-approval
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ConfigBackup(Base):
    __tablename__ = "config_backups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="running")  # running|startup|full
    content: Mapped[str] = mapped_column(UnicodeText)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer, default=0)
    job_execution_id: Mapped[int | None] = mapped_column(ForeignKey("job_executions.id"))
    note: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class ConfigChange(Base):
    __tablename__ = "config_changes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    job_execution_id: Mapped[int | None] = mapped_column(ForeignKey("job_executions.id"))
    backup_before_id: Mapped[int | None] = mapped_column(ForeignKey("config_backups.id"))
    backup_after_id: Mapped[int | None] = mapped_column(ForeignKey("config_backups.id"))
    diff: Mapped[str] = mapped_column(UnicodeText, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    """Tamper-evident (hash-chained) audit trail. UPDATE/DELETE blocked by DB trigger on SQL Server."""
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(Integer)
    actor_name: Mapped[str] = mapped_column(String(128), default="system")
    action: Mapped[str] = mapped_column(String(100), index=True)
    target_type: Mapped[str] = mapped_column(String(50), default="")
    target_id: Mapped[str] = mapped_column(String(100), default="")
    target_name: Mapped[str] = mapped_column(String(300), default="")
    device_id: Mapped[int | None] = mapped_column(Integer, index=True)
    result: Mapped[str] = mapped_column(String(20), default="success")
    ip_address: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


# ---------------------------------------------------------------- monitoring
class AlertRule(Base):
    __tablename__ = "alert_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    metric: Mapped[str] = mapped_column(String(64))  # cpu_pct | mem_pct | disk_pct | if_util_pct | availability
    operator: Mapped[str] = mapped_column(String(4), default=">")
    threshold: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(16), default="warning")  # info|warning|critical
    device_type: Mapped[str | None] = mapped_column(String(32))
    device_group_id: Mapped[int | None] = mapped_column(ForeignKey("device_groups.id"))
    notify_email: Mapped[str | None] = mapped_column(String(1000))
    escalate_after_minutes: Mapped[int | None] = mapped_column(Integer)
    escalation_email: Mapped[str | None] = mapped_column(String(1000))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("alert_rules.id"))
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), index=True)
    source: Mapped[str] = mapped_column(String(32), default="rule")
    severity: Mapped[str] = mapped_column(String(16), default="warning", index=True)
    title: Mapped[str] = mapped_column(String(300))
    message: Mapped[str] = mapped_column(String(2000), default="")
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    fingerprint: Mapped[str] = mapped_column(String(200), index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(String(2000), default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    link: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    read_at: Mapped[datetime | None] = mapped_column(DateTime)


class Metric(Base):
    __tablename__ = "monitoring_metrics"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    metric: Mapped[str] = mapped_column(String(64))
    value: Mapped[float] = mapped_column(Float)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (Index("ix_metrics_device_metric_ts", "device_id", "metric", "ts"),)


class SystemSetting(Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by: Mapped[int | None] = mapped_column(Integer)


# ---------------------------------------------------------------- Group Policy (1.1)
class GpoCollection(Base):
    """One collection of all GPOs of a domain (from a DC over WinRM, or an uploaded Get-GPOReport XML)."""
    __tablename__ = "gpo_collections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(16), default="device")  # device | upload
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"))
    job_execution_id: Mapped[int | None] = mapped_column(Integer)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    collected_by: Mapped[str] = mapped_column(String(128), default="system")
    domain_info: Mapped[dict] = mapped_column(JSON, default=dict)
    ou_data: Mapped[list] = mapped_column(JSON, default=list)   # [{path, dn, blocked, links:[{guid,order,enforced,enabled}], inherited:[guid...]}]
    extra: Mapped[dict] = mapped_column(JSON, default=dict)     # sysvol checks, domain controllers, collector warnings
    gpo_count: Mapped[int] = mapped_column(Integer, default=0)
    changed_count: Mapped[int] = mapped_column(Integer, default=0)
    note: Mapped[str] = mapped_column(String(500), default="")


class GpoSnapshot(Base):
    """A distinct version of one GPO's XML report. Stored once per content hash; collections reference it."""
    __tablename__ = "gpo_snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255))
    guid: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    xml: Mapped[str] = mapped_column(UnicodeText)
    first_collection_id: Mapped[int | None] = mapped_column(ForeignKey("gpo_collections.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("domain", "guid", "sha256", name="uq_gpo_snapshot_content"),)


class GpoCollectionItem(Base):
    __tablename__ = "gpo_collection_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    collection_id: Mapped[int] = mapped_column(ForeignKey("gpo_collections.id"), index=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("gpo_snapshots.id"))
    guid: Mapped[str] = mapped_column(String(40))
    changed: Mapped[bool] = mapped_column(Boolean, default=False)  # differs from the previous collection of the domain


# ---------------------------------------------------------------- Active Directory inventory (1.1)
class AdDomain(Base):
    __tablename__ = "ad_domains"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)       # DNS name, e.g. corp.local
    ldap_url: Mapped[str] = mapped_column(String(500))                # ldaps://dc01.corp.local:636
    base_dn: Mapped[str] = mapped_column(String(500))
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id"))
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    start_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_interval_hours: Mapped[int] = mapped_column(Integer, default=6)
    stale_days: Mapped[int] = mapped_column(Integer, default=90)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_sync_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_sync_message: Mapped[str | None] = mapped_column(String(1000))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AdObject(Base):
    __tablename__ = "ad_objects"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("ad_domains.id"))
    kind: Mapped[str] = mapped_column(String(16))  # user | computer | group | ou | dc
    guid: Mapped[str] = mapped_column(String(40))
    dn: Mapped[str] = mapped_column(String(1000))
    sam: Mapped[str] = mapped_column(String(256), default="")
    name: Mapped[str] = mapped_column(String(400), default="")
    display_name: Mapped[str] = mapped_column(String(400), default="")
    enabled: Mapped[bool | None] = mapped_column(Boolean)
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    locked: Mapped[bool] = mapped_column(Boolean, default=False)
    pwd_never_expires: Mapped[bool] = mapped_column(Boolean, default=False)
    last_logon: Mapped[datetime | None] = mapped_column(DateTime)
    pwd_last_set: Mapped[datetime | None] = mapped_column(DateTime)
    account_expires: Mapped[datetime | None] = mapped_column(DateTime)
    when_created: Mapped[datetime | None] = mapped_column(DateTime)
    when_changed: Mapped[datetime | None] = mapped_column(DateTime)
    os: Mapped[str] = mapped_column(String(200), default="")
    attrs: Mapped[dict] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("domain_id", "guid", name="uq_ad_object_guid"), Index("ix_ad_objects_domain_kind", "domain_id", "kind"))


class AdChange(Base):
    """Differences detected between two synchronisations (created, deleted, enabled/disabled, privileged membership)."""
    __tablename__ = "ad_changes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("ad_domains.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(16))
    guid: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(400))
    change: Mapped[str] = mapped_column(String(40))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


# ---------------------------------------------------------------- IT audit & compliance (1.1)
class ComplianceFramework(Base):
    __tablename__ = "compliance_frameworks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(40), default="")
    description: Mapped[str] = mapped_column(String(2000), default="")
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework_id: Mapped[int] = mapped_column(ForeignKey("compliance_frameworks.id"), index=True)
    ref: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(400))
    description: Mapped[str] = mapped_column(UnicodeText, default="")
    domain: Mapped[str] = mapped_column(String(150), default="")
    check_keys: Mapped[list] = mapped_column(JSON, default=list)   # automated checks mapped to this control
    guidance: Mapped[str] = mapped_column(String(2000), default="")
    sort: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("framework_id", "ref", name="uq_control_ref"),)


class Assessment(Base):
    __tablename__ = "compliance_assessments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    framework_id: Mapped[int] = mapped_column(ForeignKey("compliance_frameworks.id"))
    period_start: Mapped[datetime | None] = mapped_column(DateTime)
    period_end: Mapped[datetime | None] = mapped_column(DateTime)
    scope: Mapped[dict] = mapped_column(JSON, default=dict)  # {description, sites, device_groups, domains}
    status: Mapped[str] = mapped_column(String(16), default="draft")  # draft | in_review | approved
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    executive_summary: Mapped[str] = mapped_column(UnicodeText, default="")
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime)
    approval_comment: Mapped[str] = mapped_column(String(2000), default="")


class AssessmentResult(Base):
    __tablename__ = "assessment_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("compliance_assessments.id"), index=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("compliance_controls.id"))
    status: Mapped[str] = mapped_column(String(20), default="not_assessed")  # compliant|partial|non_compliant|not_assessed|not_applicable
    source: Mapped[str] = mapped_column(String(120), default="")             # automated:<check> | manual
    evidence_summary: Mapped[str] = mapped_column(UnicodeText, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)               # [{type: system|file, ref, label, sha256, ts}]
    assessed_at: Mapped[datetime | None] = mapped_column(DateTime)
    assessed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    auditor_notes: Mapped[str] = mapped_column(UnicodeText, default="")
    __table_args__ = (UniqueConstraint("assessment_id", "control_id", name="uq_assessment_control"),)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey("compliance_assessments.id"), index=True)
    control_id: Mapped[int | None] = mapped_column(ForeignKey("compliance_controls.id"))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(UnicodeText, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)  # critical|high|medium|low|informational
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)      # open|assigned|in_progress|pending_verification|closed|accepted_risk
    source: Mapped[str] = mapped_column(String(120), default="manual")
    asset: Mapped[str] = mapped_column(String(300), default="")
    root_cause: Mapped[str] = mapped_column(UnicodeText, default="")
    business_impact: Mapped[str] = mapped_column(UnicodeText, default="")
    recommendation: Mapped[str] = mapped_column(UnicodeText, default="")
    owner_department: Mapped[str] = mapped_column(String(150), default="")
    owner_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    due_date: Mapped[datetime | None] = mapped_column(DateTime)
    fingerprint: Mapped[str | None] = mapped_column(String(200), index=True)
    risk_acceptance: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime)


class FindingEvent(Base):
    __tablename__ = "finding_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    from_status: Mapped[str | None] = mapped_column(String(24))
    to_status: Mapped[str | None] = mapped_column(String(24))
    comment: Mapped[str] = mapped_column(String(2000), default="")


class Evidence(Base):
    """Evidence repository. Content is immutable; its SHA-256 is recorded at upload and re-verified on download."""
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(String(2000), default="")
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(150), default="application/octet-stream")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    content: Mapped[bytes] = mapped_column(LargeBinary().with_variant(VARBINARY("max"), "mssql"))
    source: Mapped[str] = mapped_column(String(40), default="upload")  # upload | system
    assessment_id: Mapped[int | None] = mapped_column(ForeignKey("compliance_assessments.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), index=True)
    control_ref: Mapped[str | None] = mapped_column(String(80))
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime)
    withdrawn_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    withdrawn_reason: Mapped[str | None] = mapped_column(String(1000))


# ---------------------------------------------------------------- Report Center (1.1)
class ReportSchedule(Base):
    __tablename__ = "report_schedules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True)
    report_key: Mapped[str] = mapped_column(String(60))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    format: Mapped[str] = mapped_column(String(8), default="pdf")
    cron: Mapped[str] = mapped_column(String(100))
    recipients: Mapped[str] = mapped_column(String(1000), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_status: Mapped[str | None] = mapped_column(String(20))
    last_message: Mapped[str | None] = mapped_column(String(1000))


class ReportRun(Base):
    """A generated report file kept for the history (Reports -> Historical reports)."""
    __tablename__ = "report_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_key: Mapped[str] = mapped_column(String(60), index=True)
    title: Mapped[str] = mapped_column(String(300))
    format: Mapped[str] = mapped_column(String(8))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    generated_by: Mapped[str] = mapped_column(String(128), default="system")
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("report_schedules.id"))
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    content: Mapped[bytes] = mapped_column(LargeBinary().with_variant(VARBINARY("max"), "mssql"))
    emailed_to: Mapped[str] = mapped_column(String(1000), default="")
