BEGIN TRANSACTION;

CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

GO

-- Running upgrade  -> 0001_initial

CREATE TABLE approval_policies (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    risk VARCHAR(16) NULL, 
    category VARCHAR(32) NULL, 
    environment VARCHAR(20) NULL, 
    require_approval BIT NOT NULL, 
    require_maintenance_window BIT NOT NULL, 
    enabled BIT NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (name)
);

GO

CREATE TABLE audit_logs (
    id BIGINT NOT NULL IDENTITY, 
    ts DATETIME NOT NULL, 
    actor_user_id INTEGER NULL, 
    actor_name VARCHAR(128) NOT NULL, 
    action VARCHAR(100) NOT NULL, 
    target_type VARCHAR(50) NOT NULL, 
    target_id VARCHAR(100) NOT NULL, 
    target_name VARCHAR(300) NOT NULL, 
    device_id INTEGER NULL, 
    result VARCHAR(20) NOT NULL, 
    ip_address VARCHAR(64) NULL, 
    details NVARCHAR(max) NOT NULL, 
    prev_hash VARCHAR(64) NOT NULL, 
    hash VARCHAR(64) NOT NULL, 
    PRIMARY KEY (id)
);

GO

CREATE INDEX ix_audit_logs_action ON audit_logs (action);

GO

CREATE INDEX ix_audit_logs_device_id ON audit_logs (device_id);

GO

CREATE INDEX ix_audit_logs_ts ON audit_logs (ts);

GO

CREATE TABLE device_groups (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    description VARCHAR(500) NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (name)
);

GO

CREATE TABLE job_templates (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    description VARCHAR(1000) NOT NULL, 
    kind VARCHAR(16) NOT NULL, 
    category VARCHAR(32) NOT NULL, 
    operation_id VARCHAR(100) NULL, 
    playbook VARCHAR(200) NULL, 
    default_params NVARCHAR(max) NOT NULL, 
    param_schema NVARCHAR(max) NOT NULL, 
    risk VARCHAR(16) NOT NULL, 
    supports_check_mode BIT NOT NULL, 
    is_builtin BIT NOT NULL, 
    enabled BIT NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (name)
);

GO

CREATE TABLE permissions (
    id INTEGER NOT NULL IDENTITY, 
    code VARCHAR(100) NOT NULL, 
    description VARCHAR(300) NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (code)
);

GO

CREATE TABLE roles (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(100) NOT NULL, 
    description VARCHAR(500) NOT NULL, 
    is_builtin BIT NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (name)
);

GO

CREATE TABLE sites (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    kind VARCHAR(20) NOT NULL, 
    address VARCHAR(300) NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (name)
);

GO

CREATE TABLE system_settings (
    [key] VARCHAR(100) NOT NULL, 
    value NVARCHAR(max) NOT NULL, 
    updated_at DATETIME NOT NULL, 
    updated_by INTEGER NULL, 
    PRIMARY KEY ([key])
);

GO

CREATE TABLE vault_secrets (
    id INTEGER NOT NULL IDENTITY, 
    purpose VARCHAR(100) NOT NULL, 
    ciphertext IMAGE NOT NULL, 
    nonce IMAGE NOT NULL, 
    wrapped_key IMAGE NOT NULL, 
    key_nonce IMAGE NOT NULL, 
    key_version INTEGER NOT NULL, 
    created_at DATETIME NOT NULL, 
    rotated_at DATETIME NULL, 
    PRIMARY KEY (id)
);

GO

CREATE TABLE alert_rules (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    metric VARCHAR(64) NOT NULL, 
    operator VARCHAR(4) NOT NULL, 
    threshold FLOAT NOT NULL, 
    severity VARCHAR(16) NOT NULL, 
    device_type VARCHAR(32) NULL, 
    device_group_id INTEGER NULL, 
    notify_email VARCHAR(1000) NULL, 
    escalate_after_minutes INTEGER NULL, 
    escalation_email VARCHAR(1000) NULL, 
    enabled BIT NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(device_group_id) REFERENCES device_groups (id), 
    UNIQUE (name)
);

GO

CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL, 
    permission_id INTEGER NOT NULL, 
    PRIMARY KEY (role_id, permission_id), 
    FOREIGN KEY(permission_id) REFERENCES permissions (id), 
    FOREIGN KEY(role_id) REFERENCES roles (id)
);

GO

CREATE TABLE users (
    id INTEGER NOT NULL IDENTITY, 
    username VARCHAR(128) NOT NULL, 
    display_name VARCHAR(200) NOT NULL, 
    email VARCHAR(254) NULL, 
    auth_source VARCHAR(16) NOT NULL, 
    password_hash VARCHAR(200) NULL, 
    is_active BIT NOT NULL, 
    mfa_enabled BIT NOT NULL, 
    mfa_secret_id INTEGER NULL, 
    failed_attempts INTEGER NOT NULL, 
    locked_until DATETIME NULL, 
    must_change_password BIT NOT NULL, 
    last_login_at DATETIME NULL, 
    created_at DATETIME NOT NULL, 
    updated_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(mfa_secret_id) REFERENCES vault_secrets (id)
);

GO

CREATE UNIQUE INDEX ix_users_username ON users (username);

GO

CREATE TABLE credentials (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    kind VARCHAR(32) NOT NULL, 
    username VARCHAR(200) NULL, 
    secret_id INTEGER NULL, 
    extra NVARCHAR(max) NOT NULL, 
    description VARCHAR(500) NOT NULL, 
    created_by INTEGER NULL, 
    created_at DATETIME NOT NULL, 
    updated_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(created_by) REFERENCES users (id), 
    FOREIGN KEY(secret_id) REFERENCES vault_secrets (id), 
    UNIQUE (name)
);

GO

CREATE TABLE jobs (
    id INTEGER NOT NULL IDENTITY, 
    title VARCHAR(300) NOT NULL, 
    kind VARCHAR(16) NOT NULL, 
    template_id INTEGER NULL, 
    operation_id VARCHAR(100) NULL, 
    playbook VARCHAR(200) NULL, 
    category VARCHAR(32) NOT NULL, 
    params NVARCHAR(max) NOT NULL, 
    change_summary NTEXT NOT NULL, 
    requested_by INTEGER NULL, 
    status VARCHAR(24) NOT NULL, 
    check_mode BIT NOT NULL, 
    risk VARCHAR(16) NOT NULL, 
    is_emergency BIT NOT NULL, 
    requires_window BIT NOT NULL, 
    timeout_seconds INTEGER NOT NULL, 
    cancel_requested BIT NOT NULL, 
    worker_id VARCHAR(100) NULL, 
    summary VARCHAR(1000) NULL, 
    created_at DATETIME NOT NULL, 
    queued_at DATETIME NULL, 
    started_at DATETIME NULL, 
    finished_at DATETIME NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(requested_by) REFERENCES users (id), 
    FOREIGN KEY(template_id) REFERENCES job_templates (id)
);

GO

CREATE INDEX ix_jobs_created_at ON jobs (created_at);

GO

CREATE INDEX ix_jobs_status ON jobs (status);

GO

CREATE TABLE maintenance_windows (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    start_at DATETIME NOT NULL, 
    end_at DATETIME NOT NULL, 
    environment VARCHAR(20) NULL, 
    device_group_id INTEGER NULL, 
    auto_approve_change BIT NOT NULL, 
    created_by INTEGER NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(created_by) REFERENCES users (id), 
    FOREIGN KEY(device_group_id) REFERENCES device_groups (id)
);

GO

CREATE TABLE notifications (
    id INTEGER NOT NULL IDENTITY, 
    user_id INTEGER NOT NULL, 
    title VARCHAR(300) NOT NULL, 
    body VARCHAR(2000) NOT NULL, 
    severity VARCHAR(16) NOT NULL, 
    link VARCHAR(300) NULL, 
    created_at DATETIME NOT NULL, 
    read_at DATETIME NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id)
);

GO

CREATE INDEX ix_notifications_user_id ON notifications (user_id);

GO

CREATE TABLE saved_filters (
    id INTEGER NOT NULL IDENTITY, 
    user_id INTEGER NOT NULL, 
    name VARCHAR(150) NOT NULL, 
    module VARCHAR(50) NOT NULL, 
    filter NVARCHAR(max) NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id)
);

GO

CREATE INDEX ix_saved_filters_user_id ON saved_filters (user_id);

GO

CREATE TABLE user_roles (
    id INTEGER NOT NULL IDENTITY, 
    user_id INTEGER NOT NULL, 
    role_id INTEGER NOT NULL, 
    device_group_id INTEGER NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(device_group_id) REFERENCES device_groups (id), 
    FOREIGN KEY(role_id) REFERENCES roles (id), 
    FOREIGN KEY(user_id) REFERENCES users (id), 
    CONSTRAINT uq_user_role_scope UNIQUE (user_id, role_id, device_group_id)
);

GO

CREATE INDEX ix_user_roles_user_id ON user_roles (user_id);

GO

CREATE TABLE user_sessions (
    id INTEGER NOT NULL IDENTITY, 
    user_id INTEGER NOT NULL, 
    token_hash VARCHAR(64) NOT NULL, 
    created_at DATETIME NOT NULL, 
    expires_at DATETIME NOT NULL, 
    last_seen_at DATETIME NOT NULL, 
    ip_address VARCHAR(64) NULL, 
    user_agent VARCHAR(300) NULL, 
    revoked BIT NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id), 
    UNIQUE (token_hash)
);

GO

CREATE INDEX ix_user_sessions_user_id ON user_sessions (user_id);

GO

CREATE TABLE approvals (
    id INTEGER NOT NULL IDENTITY, 
    job_id INTEGER NOT NULL, 
    requested_by INTEGER NULL, 
    status VARCHAR(16) NOT NULL, 
    kind VARCHAR(16) NOT NULL, 
    reason VARCHAR(2000) NOT NULL, 
    decided_by INTEGER NULL, 
    decided_at DATETIME NULL, 
    decision_comment VARCHAR(2000) NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(decided_by) REFERENCES users (id), 
    FOREIGN KEY(job_id) REFERENCES jobs (id), 
    FOREIGN KEY(requested_by) REFERENCES users (id)
);

GO

CREATE INDEX ix_approvals_job_id ON approvals (job_id);

GO

CREATE INDEX ix_approvals_status ON approvals (status);

GO

CREATE TABLE devices (
    id INTEGER NOT NULL IDENTITY, 
    hostname VARCHAR(253) NOT NULL, 
    ip_address VARCHAR(64) NOT NULL, 
    device_type VARCHAR(32) NOT NULL, 
    platform VARCHAR(48) NOT NULL, 
    os_name VARCHAR(120) NOT NULL, 
    os_version VARCHAR(120) NOT NULL, 
    vendor VARCHAR(120) NOT NULL, 
    model VARCHAR(120) NOT NULL, 
    firmware VARCHAR(120) NOT NULL, 
    serial_number VARCHAR(120) NOT NULL, 
    owner VARCHAR(150) NOT NULL, 
    site_id INTEGER NULL, 
    department VARCHAR(120) NOT NULL, 
    location VARCHAR(200) NOT NULL, 
    environment VARCHAR(20) NOT NULL, 
    tags NVARCHAR(max) NOT NULL, 
    port INTEGER NULL, 
    verify_tls BIT NOT NULL, 
    credential_id INTEGER NULL, 
    snmp_credential_id INTEGER NULL, 
    is_simulated BIT NOT NULL, 
    monitoring_enabled BIT NOT NULL, 
    status VARCHAR(16) NOT NULL, 
    last_checked_at DATETIME NULL, 
    last_success_at DATETIME NULL, 
    last_error VARCHAR(1000) NULL, 
    notes NTEXT NOT NULL, 
    created_at DATETIME NOT NULL, 
    updated_at DATETIME NOT NULL, 
    deleted_at DATETIME NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(credential_id) REFERENCES credentials (id), 
    FOREIGN KEY(site_id) REFERENCES sites (id), 
    FOREIGN KEY(snmp_credential_id) REFERENCES credentials (id)
);

GO

CREATE INDEX ix_devices_deleted_at ON devices (deleted_at);

GO

CREATE INDEX ix_devices_device_type ON devices (device_type);

GO

CREATE INDEX ix_devices_environment ON devices (environment);

GO

CREATE INDEX ix_devices_hostname ON devices (hostname);

GO

CREATE INDEX ix_devices_ip_address ON devices (ip_address);

GO

CREATE INDEX ix_devices_type_env ON devices (device_type, environment);

GO

CREATE TABLE integrations (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    kind VARCHAR(32) NOT NULL, 
    base_url VARCHAR(500) NOT NULL, 
    credential_id INTEGER NULL, 
    verify_tls BIT NOT NULL, 
    settings NVARCHAR(max) NOT NULL, 
    enabled BIT NOT NULL, 
    last_test_at DATETIME NULL, 
    last_test_ok BIT NULL, 
    last_test_message VARCHAR(1000) NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(credential_id) REFERENCES credentials (id), 
    UNIQUE (name)
);

GO

CREATE TABLE alerts (
    id INTEGER NOT NULL IDENTITY, 
    rule_id INTEGER NULL, 
    device_id INTEGER NULL, 
    source VARCHAR(32) NOT NULL, 
    severity VARCHAR(16) NOT NULL, 
    title VARCHAR(300) NOT NULL, 
    message VARCHAR(2000) NOT NULL, 
    status VARCHAR(16) NOT NULL, 
    fingerprint VARCHAR(200) NOT NULL, 
    count INTEGER NOT NULL, 
    first_seen_at DATETIME NOT NULL, 
    last_seen_at DATETIME NOT NULL, 
    acknowledged_by INTEGER NULL, 
    acknowledged_at DATETIME NULL, 
    resolved_at DATETIME NULL, 
    escalated_at DATETIME NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(acknowledged_by) REFERENCES users (id), 
    FOREIGN KEY(device_id) REFERENCES devices (id), 
    FOREIGN KEY(rule_id) REFERENCES alert_rules (id)
);

GO

CREATE INDEX ix_alerts_device_id ON alerts (device_id);

GO

CREATE INDEX ix_alerts_fingerprint ON alerts (fingerprint);

GO

CREATE INDEX ix_alerts_severity ON alerts (severity);

GO

CREATE INDEX ix_alerts_status ON alerts (status);

GO

CREATE TABLE device_group_members (
    group_id INTEGER NOT NULL, 
    device_id INTEGER NOT NULL, 
    PRIMARY KEY (group_id, device_id), 
    FOREIGN KEY(device_id) REFERENCES devices (id), 
    FOREIGN KEY(group_id) REFERENCES device_groups (id)
);

GO

CREATE TABLE job_executions (
    id INTEGER NOT NULL IDENTITY, 
    job_id INTEGER NOT NULL, 
    device_id INTEGER NOT NULL, 
    status VARCHAR(24) NOT NULL, 
    output NTEXT NOT NULL, 
    error NTEXT NULL, 
    result NVARCHAR(max) NOT NULL, 
    before_state NTEXT NULL, 
    after_state NTEXT NULL, 
    verification NTEXT NULL, 
    rollback_hint NTEXT NULL, 
    started_at DATETIME NULL, 
    finished_at DATETIME NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(device_id) REFERENCES devices (id), 
    FOREIGN KEY(job_id) REFERENCES jobs (id)
);

GO

CREATE INDEX ix_job_executions_device_id ON job_executions (device_id);

GO

CREATE INDEX ix_job_executions_job_id ON job_executions (job_id);

GO

CREATE TABLE monitoring_metrics (
    id BIGINT NOT NULL IDENTITY, 
    device_id INTEGER NOT NULL, 
    metric VARCHAR(64) NOT NULL, 
    value FLOAT NOT NULL, 
    ts DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(device_id) REFERENCES devices (id)
);

GO

CREATE INDEX ix_metrics_device_metric_ts ON monitoring_metrics (device_id, metric, ts);

GO

CREATE TABLE config_backups (
    id INTEGER NOT NULL IDENTITY, 
    device_id INTEGER NOT NULL, 
    kind VARCHAR(16) NOT NULL, 
    content NTEXT NOT NULL, 
    sha256 VARCHAR(64) NOT NULL, 
    size INTEGER NOT NULL, 
    job_execution_id INTEGER NULL, 
    note VARCHAR(500) NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(device_id) REFERENCES devices (id), 
    FOREIGN KEY(job_execution_id) REFERENCES job_executions (id)
);

GO

CREATE INDEX ix_config_backups_created_at ON config_backups (created_at);

GO

CREATE INDEX ix_config_backups_device_id ON config_backups (device_id);

GO

CREATE TABLE config_changes (
    id INTEGER NOT NULL IDENTITY, 
    device_id INTEGER NOT NULL, 
    job_execution_id INTEGER NULL, 
    backup_before_id INTEGER NULL, 
    backup_after_id INTEGER NULL, 
    diff NTEXT NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(backup_after_id) REFERENCES config_backups (id), 
    FOREIGN KEY(backup_before_id) REFERENCES config_backups (id), 
    FOREIGN KEY(device_id) REFERENCES devices (id), 
    FOREIGN KEY(job_execution_id) REFERENCES job_executions (id)
);

GO

CREATE INDEX ix_config_changes_device_id ON config_changes (device_id);

GO

CREATE TRIGGER trg_audit_logs_immutable ON audit_logs INSTEAD OF UPDATE, DELETE AS BEGIN SET NOCOUNT ON; THROW 51000, 'audit_logs is append-only', 1; END;

GO

INSERT INTO alembic_version (version_num) OUTPUT inserted.version_num VALUES ('0001_initial');

GO

-- Running upgrade 0001_initial -> 0002

CREATE TABLE job_schedules (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    description VARCHAR(1000) NOT NULL, 
    kind VARCHAR(16) NOT NULL, 
    operation_id VARCHAR(100) NULL, 
    template_id INTEGER NULL, 
    device_ids NVARCHAR(max) NOT NULL, 
    params NVARCHAR(max) NOT NULL, 
    check_mode BIT NOT NULL, 
    cron VARCHAR(100) NOT NULL, 
    enabled BIT NOT NULL, 
    created_by INTEGER NOT NULL, 
    next_run_at DATETIME NULL, 
    last_run_at DATETIME NULL, 
    last_job_id INTEGER NULL, 
    last_error VARCHAR(1000) NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(created_by) REFERENCES users (id), 
    FOREIGN KEY(template_id) REFERENCES job_templates (id), 
    UNIQUE (name)
);

GO

CREATE INDEX ix_job_schedules_next_run_at ON job_schedules (next_run_at);

GO

UPDATE alembic_version SET version_num='0002' WHERE alembic_version.version_num = '0001_initial';

GO

-- Running upgrade 0002 -> 0003

CREATE TABLE scripts (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    description VARCHAR(1000) NOT NULL, 
    target VARCHAR(20) NOT NULL, 
    mode VARCHAR(10) NOT NULL, 
    risk VARCHAR(10) NOT NULL, 
    body NTEXT NOT NULL, 
    params NVARCHAR(max) NOT NULL, 
    run_as_root BIT NOT NULL, 
    save_config BIT NOT NULL, 
    timeout_seconds INTEGER NOT NULL, 
    version INTEGER NOT NULL, 
    sha256 VARCHAR(64) NOT NULL, 
    status VARCHAR(12) NOT NULL, 
    created_by INTEGER NOT NULL, 
    updated_by INTEGER NOT NULL, 
    approved_by INTEGER NULL, 
    approved_at DATETIME NULL, 
    approved_sha256 VARCHAR(64) NULL, 
    review_comment VARCHAR(1000) NOT NULL, 
    created_at DATETIME NOT NULL, 
    updated_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(approved_by) REFERENCES users (id), 
    FOREIGN KEY(created_by) REFERENCES users (id), 
    FOREIGN KEY(updated_by) REFERENCES users (id), 
    UNIQUE (name)
);

GO

UPDATE alembic_version SET version_num='0003' WHERE alembic_version.version_num = '0002';

GO

-- Running upgrade 0003 -> 0004

CREATE TABLE compliance_frameworks (
    id INTEGER NOT NULL IDENTITY, 
    code VARCHAR(40) NOT NULL, 
    name VARCHAR(200) NOT NULL, 
    version VARCHAR(40) NOT NULL, 
    description VARCHAR(2000) NOT NULL, 
    is_builtin BIT NOT NULL, 
    enabled BIT NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    UNIQUE (code)
);

GO

CREATE TABLE compliance_controls (
    id INTEGER NOT NULL IDENTITY, 
    framework_id INTEGER NOT NULL, 
    ref VARCHAR(40) NOT NULL, 
    title VARCHAR(400) NOT NULL, 
    description NTEXT NOT NULL, 
    domain VARCHAR(150) NOT NULL, 
    check_keys NVARCHAR(max) NOT NULL, 
    guidance VARCHAR(2000) NOT NULL, 
    sort INTEGER NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(framework_id) REFERENCES compliance_frameworks (id), 
    CONSTRAINT uq_control_ref UNIQUE (framework_id, ref)
);

GO

CREATE INDEX ix_compliance_controls_framework_id ON compliance_controls (framework_id);

GO

CREATE TABLE compliance_assessments (
    id INTEGER NOT NULL IDENTITY, 
    title VARCHAR(300) NOT NULL, 
    framework_id INTEGER NOT NULL, 
    period_start DATETIME NULL, 
    period_end DATETIME NULL, 
    scope NVARCHAR(max) NOT NULL, 
    status VARCHAR(16) NOT NULL, 
    summary NVARCHAR(max) NOT NULL, 
    executive_summary NTEXT NOT NULL, 
    created_by INTEGER NOT NULL, 
    created_at DATETIME NOT NULL, 
    submitted_at DATETIME NULL, 
    approved_by INTEGER NULL, 
    approved_at DATETIME NULL, 
    approval_comment VARCHAR(2000) NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(approved_by) REFERENCES users (id), 
    FOREIGN KEY(created_by) REFERENCES users (id), 
    FOREIGN KEY(framework_id) REFERENCES compliance_frameworks (id)
);

GO

CREATE TABLE report_schedules (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(150) NOT NULL, 
    report_key VARCHAR(60) NOT NULL, 
    params NVARCHAR(max) NOT NULL, 
    format VARCHAR(8) NOT NULL, 
    cron VARCHAR(100) NOT NULL, 
    recipients VARCHAR(1000) NOT NULL, 
    enabled BIT NOT NULL, 
    created_by INTEGER NOT NULL, 
    created_at DATETIME NOT NULL, 
    next_run_at DATETIME NULL, 
    last_run_at DATETIME NULL, 
    last_status VARCHAR(20) NULL, 
    last_message VARCHAR(1000) NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(created_by) REFERENCES users (id), 
    UNIQUE (name)
);

GO

CREATE INDEX ix_report_schedules_next_run_at ON report_schedules (next_run_at);

GO

CREATE TABLE ad_domains (
    id INTEGER NOT NULL IDENTITY, 
    name VARCHAR(255) NOT NULL, 
    ldap_url VARCHAR(500) NOT NULL, 
    base_dn VARCHAR(500) NOT NULL, 
    credential_id INTEGER NULL, 
    verify_tls BIT NOT NULL, 
    start_tls BIT NOT NULL, 
    enabled BIT NOT NULL, 
    sync_interval_hours INTEGER NOT NULL, 
    stale_days INTEGER NOT NULL, 
    settings NVARCHAR(max) NOT NULL, 
    last_sync_at DATETIME NULL, 
    last_sync_ok BIT NULL, 
    last_sync_message VARCHAR(1000) NULL, 
    last_success_at DATETIME NULL, 
    stats NVARCHAR(max) NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(credential_id) REFERENCES credentials (id), 
    UNIQUE (name)
);

GO

CREATE TABLE assessment_results (
    id INTEGER NOT NULL IDENTITY, 
    assessment_id INTEGER NOT NULL, 
    control_id INTEGER NOT NULL, 
    status VARCHAR(20) NOT NULL, 
    source VARCHAR(120) NOT NULL, 
    evidence_summary NTEXT NOT NULL, 
    evidence NVARCHAR(max) NOT NULL, 
    assessed_at DATETIME NULL, 
    assessed_by INTEGER NULL, 
    auditor_notes NTEXT NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(assessed_by) REFERENCES users (id), 
    FOREIGN KEY(assessment_id) REFERENCES compliance_assessments (id), 
    FOREIGN KEY(control_id) REFERENCES compliance_controls (id), 
    CONSTRAINT uq_assessment_control UNIQUE (assessment_id, control_id)
);

GO

CREATE INDEX ix_assessment_results_assessment_id ON assessment_results (assessment_id);

GO

CREATE TABLE findings (
    id INTEGER NOT NULL IDENTITY, 
    assessment_id INTEGER NULL, 
    control_id INTEGER NULL, 
    title VARCHAR(300) NOT NULL, 
    description NTEXT NOT NULL, 
    severity VARCHAR(16) NOT NULL, 
    status VARCHAR(24) NOT NULL, 
    source VARCHAR(120) NOT NULL, 
    asset VARCHAR(300) NOT NULL, 
    root_cause NTEXT NOT NULL, 
    business_impact NTEXT NOT NULL, 
    recommendation NTEXT NOT NULL, 
    owner_department VARCHAR(150) NOT NULL, 
    owner_user_id INTEGER NULL, 
    due_date DATETIME NULL, 
    fingerprint VARCHAR(200) NULL, 
    risk_acceptance NVARCHAR(max) NOT NULL, 
    created_by INTEGER NULL, 
    created_at DATETIME NOT NULL, 
    updated_at DATETIME NOT NULL, 
    closed_at DATETIME NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(assessment_id) REFERENCES compliance_assessments (id), 
    FOREIGN KEY(control_id) REFERENCES compliance_controls (id), 
    FOREIGN KEY(created_by) REFERENCES users (id), 
    FOREIGN KEY(owner_user_id) REFERENCES users (id)
);

GO

CREATE INDEX ix_findings_assessment_id ON findings (assessment_id);

GO

CREATE INDEX ix_findings_fingerprint ON findings (fingerprint);

GO

CREATE INDEX ix_findings_severity ON findings (severity);

GO

CREATE INDEX ix_findings_status ON findings (status);

GO

CREATE TABLE report_runs (
    id INTEGER NOT NULL IDENTITY, 
    report_key VARCHAR(60) NOT NULL, 
    title VARCHAR(300) NOT NULL, 
    format VARCHAR(8) NOT NULL, 
    params NVARCHAR(max) NOT NULL, 
    generated_at DATETIME NOT NULL, 
    generated_by VARCHAR(128) NOT NULL, 
    user_id INTEGER NULL, 
    schedule_id INTEGER NULL, 
    size INTEGER NOT NULL, 
    sha256 VARCHAR(64) NOT NULL, 
    content VARBINARY(max) NOT NULL, 
    emailed_to VARCHAR(1000) NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(schedule_id) REFERENCES report_schedules (id), 
    FOREIGN KEY(user_id) REFERENCES users (id)
);

GO

CREATE INDEX ix_report_runs_generated_at ON report_runs (generated_at);

GO

CREATE INDEX ix_report_runs_report_key ON report_runs (report_key);

GO

CREATE TABLE ad_changes (
    id INTEGER NOT NULL IDENTITY, 
    domain_id INTEGER NOT NULL, 
    ts DATETIME NOT NULL, 
    kind VARCHAR(16) NOT NULL, 
    guid VARCHAR(40) NOT NULL, 
    name VARCHAR(400) NOT NULL, 
    change VARCHAR(40) NOT NULL, 
    details NVARCHAR(max) NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(domain_id) REFERENCES ad_domains (id)
);

GO

CREATE INDEX ix_ad_changes_domain_id ON ad_changes (domain_id);

GO

CREATE INDEX ix_ad_changes_ts ON ad_changes (ts);

GO

CREATE TABLE ad_objects (
    id BIGINT NOT NULL IDENTITY, 
    domain_id INTEGER NOT NULL, 
    kind VARCHAR(16) NOT NULL, 
    guid VARCHAR(40) NOT NULL, 
    dn VARCHAR(1000) NOT NULL, 
    sam VARCHAR(256) NOT NULL, 
    name VARCHAR(400) NOT NULL, 
    display_name VARCHAR(400) NOT NULL, 
    enabled BIT NULL, 
    privileged BIT NOT NULL, 
    locked BIT NOT NULL, 
    pwd_never_expires BIT NOT NULL, 
    last_logon DATETIME NULL, 
    pwd_last_set DATETIME NULL, 
    account_expires DATETIME NULL, 
    when_created DATETIME NULL, 
    when_changed DATETIME NULL, 
    os VARCHAR(200) NOT NULL, 
    attrs NVARCHAR(max) NOT NULL, 
    synced_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(domain_id) REFERENCES ad_domains (id), 
    CONSTRAINT uq_ad_object_guid UNIQUE (domain_id, guid)
);

GO

CREATE INDEX ix_ad_objects_domain_kind ON ad_objects (domain_id, kind);

GO

CREATE TABLE evidence (
    id INTEGER NOT NULL IDENTITY, 
    title VARCHAR(300) NOT NULL, 
    description VARCHAR(2000) NOT NULL, 
    filename VARCHAR(255) NOT NULL, 
    content_type VARCHAR(150) NOT NULL, 
    size INTEGER NOT NULL, 
    sha256 VARCHAR(64) NOT NULL, 
    content VARBINARY(max) NOT NULL, 
    source VARCHAR(40) NOT NULL, 
    assessment_id INTEGER NULL, 
    finding_id INTEGER NULL, 
    control_ref VARCHAR(80) NULL, 
    uploaded_by INTEGER NULL, 
    uploaded_at DATETIME NOT NULL, 
    withdrawn_at DATETIME NULL, 
    withdrawn_by INTEGER NULL, 
    withdrawn_reason VARCHAR(1000) NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(assessment_id) REFERENCES compliance_assessments (id), 
    FOREIGN KEY(finding_id) REFERENCES findings (id), 
    FOREIGN KEY(uploaded_by) REFERENCES users (id), 
    FOREIGN KEY(withdrawn_by) REFERENCES users (id)
);

GO

CREATE INDEX ix_evidence_assessment_id ON evidence (assessment_id);

GO

CREATE INDEX ix_evidence_finding_id ON evidence (finding_id);

GO

CREATE TABLE finding_events (
    id INTEGER NOT NULL IDENTITY, 
    finding_id INTEGER NOT NULL, 
    ts DATETIME NOT NULL, 
    user_id INTEGER NULL, 
    from_status VARCHAR(24) NULL, 
    to_status VARCHAR(24) NULL, 
    comment VARCHAR(2000) NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(finding_id) REFERENCES findings (id), 
    FOREIGN KEY(user_id) REFERENCES users (id)
);

GO

CREATE INDEX ix_finding_events_finding_id ON finding_events (finding_id);

GO

CREATE TABLE gpo_collections (
    id INTEGER NOT NULL IDENTITY, 
    domain VARCHAR(255) NOT NULL, 
    source VARCHAR(16) NOT NULL, 
    device_id INTEGER NULL, 
    job_execution_id INTEGER NULL, 
    collected_at DATETIME NOT NULL, 
    collected_by VARCHAR(128) NOT NULL, 
    domain_info NVARCHAR(max) NOT NULL, 
    ou_data NVARCHAR(max) NOT NULL, 
    extra NVARCHAR(max) NOT NULL, 
    gpo_count INTEGER NOT NULL, 
    changed_count INTEGER NOT NULL, 
    note VARCHAR(500) NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(device_id) REFERENCES devices (id)
);

GO

CREATE INDEX ix_gpo_collections_collected_at ON gpo_collections (collected_at);

GO

CREATE INDEX ix_gpo_collections_domain ON gpo_collections (domain);

GO

CREATE TABLE gpo_snapshots (
    id INTEGER NOT NULL IDENTITY, 
    domain VARCHAR(255) NOT NULL, 
    guid VARCHAR(40) NOT NULL, 
    name VARCHAR(255) NOT NULL, 
    sha256 VARCHAR(64) NOT NULL, 
    xml NTEXT NOT NULL, 
    first_collection_id INTEGER NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(first_collection_id) REFERENCES gpo_collections (id), 
    CONSTRAINT uq_gpo_snapshot_content UNIQUE (domain, guid, sha256)
);

GO

CREATE INDEX ix_gpo_snapshots_guid ON gpo_snapshots (guid);

GO

CREATE TABLE gpo_collection_items (
    id INTEGER NOT NULL IDENTITY, 
    collection_id INTEGER NOT NULL, 
    snapshot_id INTEGER NOT NULL, 
    guid VARCHAR(40) NOT NULL, 
    changed BIT NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(collection_id) REFERENCES gpo_collections (id), 
    FOREIGN KEY(snapshot_id) REFERENCES gpo_snapshots (id)
);

GO

CREATE INDEX ix_gpo_collection_items_collection_id ON gpo_collection_items (collection_id);

GO

UPDATE alembic_version SET version_num='0004' WHERE alembic_version.version_num = '0003';

GO

COMMIT;

GO

