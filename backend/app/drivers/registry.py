"""Driver registry: platform key -> driver class. Add new vendors by registering a class here."""
from __future__ import annotations

from app.core.errors import Unsupported
from app.drivers.base import DeviceInfo, Driver
from app.drivers.firewall import FortiGateDriver, SophosXGSDriver
from app.drivers.linux import LinuxDriver
from app.drivers.network import (
    ArubaCXDriver, CiscoIOSDriver, HPProCurveDriver, MikroTikDriver, TPLinkJetStreamDriver,
)
from app.drivers.simulated import SimulatedDriver
from app.drivers.snmp import SnmpGenericDriver
from app.drivers.virtualization import ProxmoxDriver, VMwareDriver
from app.drivers.windows import WindowsDriver

DRIVERS: dict[str, type[Driver]] = {
    cls.key: cls for cls in (
        WindowsDriver, LinuxDriver, CiscoIOSDriver, ArubaCXDriver, HPProCurveDriver, TPLinkJetStreamDriver, MikroTikDriver,
        FortiGateDriver, SophosXGSDriver, ProxmoxDriver, VMwareDriver, SnmpGenericDriver,
    )
}


def driver_class(platform: str) -> type[Driver]:
    cls = DRIVERS.get(platform)
    if cls is None:
        raise Unsupported(f"No driver registered for platform '{platform}'")
    return cls


def build_driver(info: DeviceInfo, credential: dict | None, snmp_credential: dict | None = None, timeout: int = 60) -> Driver:
    cls = driver_class(info.platform)
    if info.is_simulated:
        return SimulatedDriver(info, credential, timeout, snmp_credential, real_cls=cls)
    return cls(info, credential, timeout=timeout, snmp_credential=snmp_credential)


def catalogue() -> list[dict]:
    return [{
        "key": cls.key, "name": cls.display_name, "vendor": cls.vendor, "category": cls.category,
        "device_types": list(cls.device_types), "credential_kinds": list(cls.credential_kinds), "default_port": cls.default_port,
        "operations": [spec.public(cls.category) for spec in cls.operations.values()],
    } for cls in DRIVERS.values()]
