"""Driver/plugin framework.

A driver wraps one management protocol for one platform family. It exposes:
* test_connection()  - real reachability + authentication check
* collect_facts()    - OS/vendor/model/serial/firmware discovery
* collect_metrics()  - numeric health metrics (cpu_pct, mem_pct, disk_pct, ...)
* operations         - a catalogue of typed, validated operations declared with @operation

Every operation declares a risk level (read | change | critical), a pydantic parameter
model (server-side validation; never free-form commands), whether it supports check
mode, which parameters are secrets (moved into the vault before a job is stored), and
a human-readable description of what it will change.

Drivers must never report success for something they did not do. Anything the target
cannot do raises Unsupported, which surfaces to the user as "unsupported" - not "failed"
and never "succeeded".
"""
from __future__ import annotations

import re

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.errors import Unsupported

Risk = Literal["read", "change", "critical"]


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StrictParams(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


@dataclass
class OperationSpec:
    id: str
    title: str
    description: str
    risk: Risk
    params: type[BaseModel] = NoParams
    check_mode: bool = False
    secret_params: tuple[str, ...] = ()
    changes: str = ""  # template using {param} placeholders, describes the change
    handler_name: str = ""

    def describe(self, params: dict) -> str:
        if not self.changes:
            return self.description
        safe = {k: ("***" if k in self.secret_params else v) for k, v in params.items()}
        try:
            return self.changes.format(**safe)
        except (KeyError, IndexError):
            return self.changes

    def public(self, category: str) -> dict:
        schema = self.params.model_json_schema()
        for sp in self.secret_params:
            if sp in schema.get("properties", {}):
                schema["properties"][sp]["format"] = "password"
        return {
            "id": self.id, "title": self.title, "description": self.description, "risk": self.risk,
            "check_mode": self.check_mode, "category": category, "params_schema": schema,
            "secret_params": list(self.secret_params),
        }


def operation(id: str, title: str, *, risk: Risk, params: type[BaseModel] = NoParams, description: str = "",
              check_mode: bool = False, secret_params: tuple[str, ...] = (), changes: str = ""):
    def deco(fn: Callable):
        fn._op_spec = OperationSpec(id=id, title=title, description=description or title, risk=risk, params=params,
                                    check_mode=check_mode, secret_params=secret_params, changes=changes,
                                    handler_name=fn.__name__)
        return fn
    return deco


@dataclass
class DeviceInfo:
    id: int
    hostname: str
    address: str
    platform: str
    device_type: str
    port: int | None = None
    verify_tls: bool = True
    environment: str = "production"
    is_simulated: bool = False


@dataclass
class OpResult:
    status: Literal["succeeded", "failed", "unsupported", "skipped"] = "succeeded"
    output: str = ""
    data: Any = None
    before: str | None = None
    after: str | None = None
    verification: str | None = None
    rollback: str | None = None
    config_backups: list[tuple[str, str]] = field(default_factory=list)  # (kind, content)
    check_mode: bool = False


@dataclass
class ConnectivityResult:
    ok: bool
    message: str
    latency_ms: float | None = None
    facts: dict = field(default_factory=dict)


class Driver:
    key: ClassVar[str] = ""
    category: ClassVar[str] = ""
    display_name: ClassVar[str] = ""
    vendor: ClassVar[str] = ""
    device_types: ClassVar[tuple[str, ...]] = ()
    credential_kinds: ClassVar[tuple[str, ...]] = ("password",)
    default_port: ClassVar[int | None] = None
    operations: ClassVar[dict[str, OperationSpec]] = {}

    def __init_subclass__(cls, **kw):
        super().__init_subclass__(**kw)
        ops: dict[str, OperationSpec] = {}
        for base in reversed(cls.__mro__[1:]):
            ops.update(getattr(base, "operations", {}) or {})
        for _, fn in inspect.getmembers(cls, predicate=inspect.isfunction):
            spec = getattr(fn, "_op_spec", None)
            if spec:
                ops[spec.id] = spec
        cls.operations = ops

    def __init__(self, device: DeviceInfo, credential: dict | None, timeout: int = 60, snmp_credential: dict | None = None):
        self.device = device
        self.cred = credential or {}
        self.snmp_cred = snmp_credential
        self.timeout = timeout

    @property
    def port(self) -> int | None:
        return self.device.port or self.default_port

    # ------------------------------------------------------------------ lifecycle
    def test_connection(self) -> ConnectivityResult:
        raise Unsupported(f"{self.display_name} driver does not implement connectivity testing")

    def collect_facts(self) -> dict:
        return {}

    def collect_metrics(self) -> dict[str, float]:
        return {}

    def close(self) -> None:
        pass

    # ------------------------------------------------------------------ operations
    @classmethod
    def get_spec(cls, op_id: str) -> OperationSpec:
        spec = cls.operations.get(op_id)
        if spec is None:
            raise Unsupported(f"Operation '{op_id}' is not supported by the {cls.display_name or cls.key} driver")
        return spec

    @classmethod
    def validate_params(cls, op_id: str, params: dict) -> BaseModel:
        return cls.get_spec(op_id).params.model_validate(params or {})

    def run(self, op_id: str, params: dict, check_mode: bool = False) -> OpResult:
        spec = self.get_spec(op_id)
        if check_mode and not spec.check_mode:
            raise Unsupported(f"'{spec.title}' does not support dry-run/check mode on {self.display_name}")
        model = spec.params.model_validate(params or {})
        handler = getattr(self, spec.handler_name)
        sig = inspect.signature(handler)
        kwargs = {"check_mode": check_mode} if "check_mode" in sig.parameters else {}
        result = handler(model, **kwargs)
        result.check_mode = check_mode
        return result

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def tls_hint(message: str) -> str:
    """Append a clear next step when an HTTPS/WinRM connection fails certificate validation."""
    if re.search(r"CERTIFICATE_VERIFY_FAILED|self[- ]signed|certificate verify failed|unable to get local issuer", message, re.I):
        return (message + " - The device presents a certificate this server does not trust (typical for a factory self-signed "
                "certificate). Either install the device's CA certificate on the InfraPilot host, or turn off 'Verify TLS certificate' "
                "for this device (device page -> Edit, or the button under the failed test).")
    return message


class ScriptRunP(StrictParams):
    """Run a library script. Only script_id / script_sha256 / values come from the job request; the
    executor fills in the reviewed body and options from the database just before running."""
    script_id: int = Field(ge=1)
    script_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    values: dict = Field(default_factory=dict)
    name: str = ""
    body: str = ""
    param_defs: list = Field(default_factory=list)
    mode: str = "change"
    run_as_root: bool = False
    save_config: bool = False
    timeout_seconds: int = 300


def require_library_body(p: ScriptRunP) -> None:
    if not p.body:
        raise RuntimeError("Script body missing: library scripts are resolved by the job executor")


PLACEHOLDER_RX = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")


def render_cli(body: str, values: dict) -> list[str]:
    """Substitute validated values into CLI lines; comment (! or #) and blank lines are dropped."""
    lines = []
    for ln in body.splitlines():
        if not ln.strip() or ln.lstrip().startswith(("!", "#")):
            continue
        lines.append(PLACEHOLDER_RX.sub(lambda m: str(values.get(m.group(1), "")), ln.rstrip()))
    return lines
