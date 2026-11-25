export type Me = {
  id: number; username: string; display_name: string; email: string | null; auth_source: string; mfa_enabled: boolean;
  must_change_password: boolean; permissions: string[]; roles: { id: number; role_id: number; role: string; scope_group_id: number | null }[];
  mfa_required_by_policy?: boolean; setup_completed?: boolean; is_active: boolean; locked: boolean; last_login_at: string | null; created_at: string | null;
  global_permissions?: string[];
};
export type Paged<T> = { items: T[]; total: number; page: number; page_size: number };
export type Site = { id: number; name: string; kind: string; location: string; device_count?: number };
export type Device = {
  id: number; hostname: string; ip_address: string; device_type: string; driver: string; vendor: string; model: string; os_name: string;
  os_version: string; environment: string; status: string; site: Site | null; department: string; owner: string; tags: string[];
  is_simulated: boolean; last_seen_at: string | null; last_success_at: string | null; firmware?: string; serial_number?: string;
  site_id?: number | null; credential_id?: number | null; snmp_credential_id?: number | null; port?: number | null;
  options?: Record<string, unknown>; notes?: string; last_error?: string | null; operations?: Operation[]; groups?: number[];
  monitoring_enabled?: boolean; location?: string;
};
export type JsonSchema = {
  type?: string; title?: string; description?: string; properties?: Record<string, JsonSchema>; required?: string[];
  enum?: (string | number)[]; const?: string; pattern?: string; minimum?: number; maximum?: number; default?: unknown;
  format?: string; writeOnly?: boolean; anyOf?: JsonSchema[]; items?: JsonSchema; additionalProperties?: JsonSchema | boolean;
  minItems?: number; maxItems?: number; maxLength?: number; $defs?: Record<string, JsonSchema>; $ref?: string;
};
export type Operation = {
  id: string; name: string; family: string; permission: string; risk: "low" | "medium" | "high" | "critical"; mutating: boolean;
  check_mode: boolean; summary: string; rollback: string; schema: JsonSchema; allowed: boolean; row_actions?: RowAction[]; view_actions?: { op: string; label: string }[];
};
/** Follow-up operation offered on each row of a read operation's result (pre-filled from the row). */
export type RowAction = {
  op: string; label: string; map: Record<string, string>; fixed: Record<string, unknown>; when: Record<string, unknown[]>;
  tone: "default" | "danger"; risk: "low" | "medium" | "high" | "critical";
};
export type ReadResult = { status: string; output: string | null; data: unknown; backups?: { id: number; kind: string; changed: boolean }[] };
export type Schedule = {
  id: number; name: string; description: string; kind: "operation" | "playbook"; operation_id: string | null; template_id: number | null;
  template_name: string | null; device_ids: number[]; devices: string[]; params: Record<string, unknown>; check_mode: boolean; cron: string;
  cron_text: string; enabled: boolean; owner: string | null; owner_id: number; next_run_at: string | null; last_run_at: string | null;
  last_job_id: number | null; last_job_status: string | null; last_error: string | null; created_at: string;
};
export type Execution = {
  id: number; device_id: number; hostname: string | null; status: string; output: string | null; data: unknown; error: string | null;
  verification: string | null; rollback_hint: string | null; started_at: string | null; finished_at: string | null;
};
export type Job = {
  waiting?: { kind: "no_approver" | "approval" | "window" | "worker_down" | "busy"; message: string; next_window_at?: string | null } | null;
  id: number; operation_id: string; kind?: string; requires_window?: boolean; title: string; status: string; risk: string; check_mode: boolean; emergency: boolean;
  approval_required: boolean; change_summary: string; requested_by: string; created_at: string; started_at: string | null;
  finished_at: string | null; summary: string | null; params: Record<string, unknown>; device_count: number; template_id: number | null;
  executions?: Execution[]; approval?: Approval | null;
  config_changes?: { id: number; device_id: number; hostname: string; diff: string; before_backup_id: number; after_backup_id: number }[];
};
export type Approval = {
  id: number; job_id: number; kind?: string; can_decide?: boolean; status: string; reason: string; decision_note: string; requested_by: string; requested_by_id: number;
  decided_by: string | null; created_at: string; expires_at: string | null; decided_at: string | null; job: Job | null;
};
export type Alert = {
  id: number; rule_id: number | null; device_id: number | null; hostname: string | null; severity: string; title: string; detail: string;
  status: string; source: string; opened_at: string; acknowledged_by: string | null; acknowledged_at: string | null; resolved_at: string | null;
  escalated_at: string | null;
};
export type Credential = { id: number; name: string; kind: string; username: string | null; description: string; key_version: string;
  created_at: string; updated_at: string; in_use: number };
export type Group = { id: number; name: string; description: string; device_count: number };
export type DriverInfo = { name: string; label: string; vendor: string; device_types: string[]; transport: string; default_port: number | null;
  credential_kinds: string[]; operations: string[]; notes: string };
export type Meta = { device_types: string[]; environments: string[]; drivers: DriverInfo[]; credential_kinds: string[]; mode: string };
export type Role = { id: number; name: string; description: string; is_builtin: boolean; permissions: string[] };
export type AuditRow = { id: number; ts: string; actor: string; action: string; target_type: string; target_id: string; result: string;
  ip: string | null; details: Record<string, unknown> | null; row_hash: string };
export type Template = { id: number; name: string; description: string; kind: string; category: string; operation_id: string | null; playbook: string | null;
  default_params: Record<string, unknown>; risk: string; is_builtin: boolean; supports_check_mode: boolean };
export type Notification = { id: number; title: string; body: string; level: string; link: string | null; read: boolean; created_at: string };
