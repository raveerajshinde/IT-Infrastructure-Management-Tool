"""Permission catalogue and built-in roles."""
from __future__ import annotations

PERMISSIONS: dict[str, str] = {
    "dashboard:read": "View dashboard",
    "devices:read": "View inventory",
    "devices:write": "Add/edit/import devices and groups",
    "devices:delete": "Delete devices",
    "credentials:read": "View credential metadata (never secrets)",
    "credentials:write": "Create/update/delete credentials",
    "windows:read": "Run read-only Windows operations",
    "windows:change": "Run changing Windows operations",
    "linux:read": "Run read-only Linux operations",
    "linux:change": "Run changing Linux operations",
    "network:read": "Run read-only network operations",
    "network:change": "Change network device configuration",
    "firewall:read": "View firewall configuration",
    "firewall:change": "Change firewall policies",
    "virtualization:read": "View hypervisors, VMs and storage",
    "virtualization:change": "Change VM lifecycle",
    "automation:read": "View jobs and templates",
    "automation:run": "Run automation templates",
    "automation:manage": "Create/edit automation templates",
    "scripts:read": "View the script library",
    "scripts:manage": "Write and edit scripts in the script library (scripts need approval before use)",
    "scripts:approve": "Review and approve library scripts for use (never your own)",
    "approvals:read": "View approval requests",
    "approvals:decide": "Approve or reject changes",
    "approvals:manage": "Manage approval policies and maintenance windows",
    "changes:emergency": "Execute emergency changes (post-review required)",
    "audit:read": "View audit logs",
    "audit:export": "Export audit reports",
    "alerts:read": "View alerts",
    "alerts:manage": "Acknowledge alerts, manage rules",
    "monitoring:read": "View metrics",
    "users:read": "View users and roles",
    "users:manage": "Manage users, roles and assignments",
    "settings:manage": "Manage system settings and LDAP",
    "integrations:manage": "Manage integrations",
    "gpo:read": "View Group Policy inventory, readable settings and reports",
    "gpo:manage": "Collect/upload Group Policy data and manage baseline exclusions",
    "ad:read": "View Active Directory inventory and reports",
    "ad:manage": "Configure AD domains, run synchronisation and bulk account actions",
    "compliance:read": "View audit assessments, findings, frameworks and evidence",
    "compliance:manage": "Run assessments, record results, manage findings and upload evidence",
    "compliance:approve": "Approve audit assessments and accept risks (never your own)",
    "reports:read": "Generate and download reports, view report history",
    "reports:manage": "Create and manage scheduled reports",
}

_ALL = list(PERMISSIONS)
_READ_ALL = [p for p in _ALL if p.endswith(":read")]

BUILTIN_ROLES: dict[str, tuple[str, list[str]]] = {
    "Super Administrator": ("Full control of the platform", _ALL),
    "Infrastructure Administrator": (
        "Manage all infrastructure; cannot manage users or system settings",
        [p for p in _ALL if p not in ("users:manage", "settings:manage")],
    ),
    "Windows Server Administrator": (
        "Windows servers and related automation",
        _READ_ALL + ["windows:change", "devices:write", "automation:run", "scripts:manage", "credentials:write"],
    ),
    "Linux Server Administrator": (
        "Linux servers and related automation",
        _READ_ALL + ["linux:change", "devices:write", "automation:run", "scripts:manage", "credentials:write"],
    ),
    "Network Administrator": (
        "Switches, routers, access points",
        _READ_ALL + ["network:change", "devices:write", "automation:run", "scripts:manage", "credentials:write"],
    ),
    "Firewall Administrator": (
        "Firewall policy and configuration",
        _READ_ALL + ["firewall:change", "devices:write", "automation:run", "scripts:manage", "credentials:write"],
    ),
    "IT Support Engineer": (
        "Day-to-day support: read everything, restart services, acknowledge alerts",
        _READ_ALL + ["alerts:manage", "automation:run"],
    ),
    "Auditor / Read Only": (
        "Read-only access including audit export",
        [p for p in _READ_ALL if p != "credentials:read"] + ["audit:export"],
    ),
    "Active Directory Administrator": (
        "Active Directory and Group Policy: inventory, reports, account actions (through approvals)",
        _READ_ALL + ["windows:change", "ad:manage", "gpo:manage", "automation:run", "reports:manage"],
    ),
    "Security Administrator": (
        "Security posture: alerts, Group Policy baseline, AD reports, audit findings and evidence",
        _READ_ALL + ["alerts:manage", "gpo:manage", "ad:manage", "compliance:manage", "reports:manage", "audit:export"],
    ),
    "Auditor / Compliance Officer": (
        "Runs and approves IT audits: assessments, findings, evidence, risk acceptance; read-only on infrastructure",
        [p for p in _READ_ALL if p != "credentials:read"] + ["audit:export", "compliance:manage", "compliance:approve", "reports:manage"],
    ),
    "Read-only Management User": (
        "Dashboards and reports for management; no operational access",
        ["dashboard:read", "alerts:read", "reports:read", "compliance:read", "gpo:read", "ad:read", "devices:read", "monitoring:read"],
    ),
}

CATEGORY_MODULE = {
    "windows": "windows",
    "linux": "linux",
    "network": "network",
    "firewall": "firewall",
    "virtualization": "virtualization",
    "storage": "virtualization",
}


def operation_permission(category: str, risk: str) -> str:
    module = CATEGORY_MODULE.get(category, category)
    return f"{module}:{'read' if risk == 'read' else 'change'}"
