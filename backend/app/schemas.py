"""Pydantic request/response schemas."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

DEVICE_TYPES = ("windows_server", "linux_server", "workstation", "switch", "router", "firewall", "access_point",
                "hypervisor", "storage", "other")
ENVIRONMENTS = ("production", "staging", "test", "development", "dr")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-_.]{0,251}[A-Za-z0-9])?$")


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------- auth
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    totp: str | None = Field(None, max_length=8)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class MfaVerifyIn(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


# ---------------------------------------------------------------- users
class UserOut(ORM):
    id: int
    username: str
    display_name: str
    email: str | None
    auth_source: str
    is_active: bool
    mfa_enabled: bool
    locked_until: datetime | None
    last_login_at: datetime | None
    must_change_password: bool
    created_at: datetime
    roles: list[dict] = []


class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._\-@]{2,128}$")
    display_name: str = Field("", max_length=200)
    email: str | None = Field(None, max_length=254)
    auth_source: Literal["local", "ldap"] = "local"
    password: str | None = Field(None, max_length=256)
    must_change_password: bool = True
    roles: list["RoleAssignmentIn"] = []


class UserUpdate(BaseModel):
    display_name: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=254)
    is_active: bool | None = None
    password: str | None = Field(None, max_length=256)
    unlock: bool = False
    reset_mfa: bool = False
    roles: list["RoleAssignmentIn"] | None = None


class RoleAssignmentIn(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    role_id: int
    device_group_id: int | None = Field(None, validation_alias=AliasChoices("device_group_id", "scope_group_id"))


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field("", max_length=500)
    permissions: list[str]


# ---------------------------------------------------------------- inventory
class DeviceIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    ip_address: str = Field(min_length=1, max_length=64)
    device_type: Literal[DEVICE_TYPES]  # type: ignore[valid-type]
    platform: str = Field(max_length=48)
    os_name: str = Field("", max_length=120)
    os_version: str = Field("", max_length=120)
    vendor: str = Field("", max_length=120)
    model: str = Field("", max_length=120)
    firmware: str = Field("", max_length=120)
    serial_number: str = Field("", max_length=120)
    owner: str = Field("", max_length=150)
    site_id: int | None = None
    department: str = Field("", max_length=120)
    location: str = Field("", max_length=200)
    environment: Literal[ENVIRONMENTS] = "production"  # type: ignore[valid-type]
    tags: list[str] = Field(default_factory=list, max_length=30)
    port: int | None = Field(None, ge=1, le=65535)
    verify_tls: bool = True
    credential_id: int | None = None
    snmp_credential_id: int | None = None
    monitoring_enabled: bool = True
    is_simulated: bool = False
    notes: str = Field("", max_length=5000)
    group_ids: list[int] = []

    @model_validator(mode="before")
    @classmethod
    def _ui_aliases(cls, data):
        """Accept the UI's field names: driver -> platform, options.verify_tls -> verify_tls, groups -> group_ids."""
        if isinstance(data, dict):
            data = dict(data)
            if "driver" in data and "platform" not in data:
                data["platform"] = data.pop("driver")
            data.pop("driver", None)
            opts = data.pop("options", None) or {}
            if "verify_tls" in opts and "verify_tls" not in data:
                data["verify_tls"] = bool(opts["verify_tls"])
            if "groups" in data and "group_ids" not in data:
                data["group_ids"] = data.pop("groups")
            data.pop("groups", None)
        return data

    @field_validator("hostname")
    @classmethod
    def _host(cls, v: str) -> str:
        if not HOST_RE.match(v):
            raise ValueError("Hostname may contain letters, digits, '-', '_' and '.' only")
        return v

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str) -> str:
        v = v.strip()
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            if HOST_RE.match(v):
                return v  # resolvable DNS name
            raise ValueError("Enter a valid IPv4/IPv6 address or DNS name")

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        out = []
        for t in v:
            t = t.strip()
            if t and not re.fullmatch(r"[A-Za-z0-9 _.:\-/]{1,50}", t):
                raise ValueError(f"Invalid tag '{t}'")
            if t:
                out.append(t)
        return out


class DeviceUpdate(DeviceIn):
    pass


class DeviceOut(ORM):
    id: int
    hostname: str
    ip_address: str
    device_type: str
    platform: str
    os_name: str
    os_version: str
    vendor: str
    model: str
    firmware: str
    serial_number: str
    owner: str
    site_id: int | None
    site_name: str | None = None
    department: str
    location: str
    environment: str
    tags: list[str]
    port: int | None
    verify_tls: bool
    credential_id: int | None
    snmp_credential_id: int | None
    monitoring_enabled: bool
    is_simulated: bool
    status: str
    last_checked_at: datetime | None
    last_success_at: datetime | None
    last_error: str | None
    notes: str
    created_at: datetime
    updated_at: datetime
    group_ids: list[int] = []


class SiteIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    kind: Literal["datacenter", "branch", "cloud", "office", "department", "location"] = "datacenter"
    address: str = Field("", max_length=300, validation_alias=AliasChoices("address", "location"))


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str = Field("", max_length=500)
    device_ids: list[int] | None = None


class SavedFilterIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    module: str = Field("devices", max_length=50)
    filter: dict = Field(validation_alias=AliasChoices("filter", "filters"))


class DiscoveryIn(BaseModel):
    cidr: str
    probe_ports: list[int] = Field(default_factory=lambda: [22, 443, 5985, 5986, 4444, 8006])

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        net = ipaddress.ip_network(v, strict=False)
        if net.version != 4 or net.num_addresses > 1024:
            raise ValueError("Discovery supports IPv4 ranges up to /22 (1024 addresses)")
        return str(net)


# ---------------------------------------------------------------- credentials
class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    kind: Literal["password", "ssh_key", "api_token", "snmpv3", "winrm"]
    username: str | None = Field(None, max_length=200)
    description: str = Field("", max_length=500)
    # secret material (write-only; never returned)
    password: str | None = Field(None, max_length=4096)
    private_key: str | None = Field(None, max_length=16384)
    passphrase: str | None = Field(None, max_length=1024)
    token: str | None = Field(None, max_length=4096)
    enable_secret: str | None = Field(None, max_length=1024)
    auth_password: str | None = Field(None, max_length=256)
    priv_password: str | None = Field(None, max_length=256)
    # non-secret options
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("extra")
    @classmethod
    def _extra(cls, v: dict) -> dict:
        allowed = {"transport", "use_ssl", "become", "host_key_policy", "auth_protocol", "priv_protocol", "domain"}
        bad = set(v) - allowed
        if bad:
            raise ValueError(f"Unsupported option(s): {', '.join(sorted(bad))}")
        return v


class CredentialOut(ORM):
    id: int
    name: str
    kind: str
    username: str | None
    description: str
    extra: dict
    has_secret: bool = False
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------- operations / jobs
class OperationRunIn(BaseModel):
    operation_id: str = Field(max_length=100)
    device_ids: list[int] = Field(min_length=1, max_length=500)
    params: dict[str, Any] = Field(default_factory=dict)
    check_mode: bool = False
    emergency: bool = False
    reason: str = Field("", max_length=2000)
    title: str | None = Field(None, max_length=300)


class TemplateRunIn(BaseModel):
    device_ids: list[int] = Field(min_length=1, max_length=500)
    params: dict[str, Any] = Field(default_factory=dict)
    check_mode: bool = False
    emergency: bool = False
    reason: str = Field("", max_length=2000)


class TemplateIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    description: str = Field("", max_length=1000)
    kind: Literal["operation", "playbook"]
    category: Literal["windows", "linux", "network", "firewall", "virtualization"] | None = None  # derived from the operation/playbook

    @model_validator(mode="before")
    @classmethod
    def _kind_alias(cls, data):
        if isinstance(data, dict) and data.get("kind") == "ansible":
            data = {**data, "kind": "playbook"}
        return data

    operation_id: str | None = None
    playbook: str | None = Field(None, pattern=r"^[A-Za-z0-9_\-]+\.ya?ml$")
    default_params: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class ApprovalDecisionIn(BaseModel):
    approve: bool
    comment: str = Field("", max_length=2000)


class ApprovalPolicyIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    risk: Literal["read", "change", "critical"] | None = None
    category: str | None = Field(None, max_length=32)
    environment: Literal[ENVIRONMENTS] | None = None  # type: ignore[valid-type]
    require_approval: bool = True
    require_maintenance_window: bool = False
    enabled: bool = True


class MaintenanceWindowIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    start_at: datetime
    end_at: datetime
    environment: Literal[ENVIRONMENTS] | None = None  # type: ignore[valid-type]
    device_group_id: int | None = None


class AlertRuleIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    metric: Literal["cpu_pct", "mem_pct", "disk_pct", "availability", "latency_ms"]
    operator: Literal[">", ">=", "<", "<="] = ">"
    threshold: float
    severity: Literal["info", "warning", "critical"] = "warning"
    device_type: str | None = None
    device_group_id: int | None = None
    notify_email: str | None = Field(None, max_length=1000)
    escalate_after_minutes: int | None = Field(None, ge=1, le=10080)
    escalation_email: str | None = Field(None, max_length=1000)
    enabled: bool = True


class IntegrationIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    kind: Literal["zabbix", "librenms"]
    base_url: str = Field(pattern=r"^https?://[A-Za-z0-9.\-:\[\]/_]+$", max_length=500)
    credential_id: int | None = None
    verify_tls: bool = True
    settings: dict = Field(default_factory=dict)
    enabled: bool = True


class Page(BaseModel):
    items: list
    total: int
    page: int
    page_size: int


UserCreate.model_rebuild()
UserUpdate.model_rebuild()
