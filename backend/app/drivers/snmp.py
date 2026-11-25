"""ICMP reachability and SNMPv3 polling (also the driver for access points / storage / generic devices)."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import subprocess
import time

from app.core.errors import DeviceConnectionError, Unsupported
from app.drivers.base import ConnectivityResult, Driver, OpResult, operation

OID = {
    "sysDescr": "1.3.6.1.2.1.1.1.0", "sysName": "1.3.6.1.2.1.1.5.0", "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2", "ifOperStatus": "1.3.6.1.2.1.2.2.1.8", "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifName": "1.3.6.1.2.1.31.1.1.1.1", "ifAlias": "1.3.6.1.2.1.31.1.1.1.18", "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6", "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2", "hrStorageDescr": "1.3.6.1.2.1.25.2.3.1.3",
    "hrStorageAllocationUnits": "1.3.6.1.2.1.25.2.3.1.4", "hrStorageSize": "1.3.6.1.2.1.25.2.3.1.5", "hrStorageUsed": "1.3.6.1.2.1.25.2.3.1.6",
    "hrStorageType": "1.3.6.1.2.1.25.2.3.1.2",
}
HR_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_DISK = "1.3.6.1.2.1.25.2.1.4"

_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")


def ping(address: str, count: int = 2, timeout: int = 2) -> tuple[bool, float | None]:
    if not _HOST_RE.match(address):
        return False, None
    try:
        ipaddress.ip_address(address)
        is_v6 = ":" in address
    except ValueError:
        is_v6 = False
    cmd = ["ping", "-6" if is_v6 else "-4", "-n", "-q", "-c", str(count), "-W", str(timeout), address]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=count * timeout + 3)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, None
    if r.returncode != 0:
        return False, None
    m = re.search(r"= [\d.]+/([\d.]+)/", r.stdout)
    return True, float(m.group(1)) if m else None


def tcp_check(address: str, port: int, timeout: float = 3.0) -> tuple[bool, float | None]:
    import socket

    t0 = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True, (time.monotonic() - t0) * 1000
    except OSError:
        return False, None


class SnmpV3Client:
    def __init__(self, address: str, cred: dict, port: int = 161, timeout: int = 3):
        self.address, self.cred, self.port, self.timeout = address, cred, port, timeout

    def _auth(self):
        from pysnmp.hlapi.v3arch.asyncio import (
            UsmUserData, usmAesCfb128Protocol, usmAesCfb256Protocol, usmDESPrivProtocol, usmHMAC192SHA256AuthProtocol,
            usmHMAC384SHA512AuthProtocol, usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, usmNoAuthProtocol, usmNoPrivProtocol,
        )
        auth_map = {"SHA": usmHMACSHAAuthProtocol, "SHA256": usmHMAC192SHA256AuthProtocol, "SHA512": usmHMAC384SHA512AuthProtocol,
                    "MD5": usmHMACMD5AuthProtocol, "NONE": usmNoAuthProtocol}
        priv_map = {"AES": usmAesCfb128Protocol, "AES256": usmAesCfb256Protocol, "DES": usmDESPrivProtocol, "NONE": usmNoPrivProtocol}
        ap = (self.cred.get("auth_protocol") or "SHA").upper()
        pp = (self.cred.get("priv_protocol") or "AES").upper()
        return UsmUserData(self.cred.get("username") or "", authKey=self.cred.get("auth_password") or None,
                           privKey=self.cred.get("priv_password") or None, authProtocol=auth_map.get(ap, usmHMACSHAAuthProtocol),
                           privProtocol=priv_map.get(pp, usmAesCfb128Protocol))

    async def _get(self, oids):
        from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, get_cmd

        target = await UdpTransportTarget.create((self.address, self.port), timeout=self.timeout, retries=1)
        err, status, _, binds = await get_cmd(SnmpEngine(), self._auth(), target, ContextData(), *[ObjectType(ObjectIdentity(o)) for o in oids])
        if err or status:
            raise DeviceConnectionError(f"SNMPv3 error: {err or status.prettyPrint()}")
        return {str(n): v for n, v in binds}

    async def _walk(self, oid):
        from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, bulk_walk_cmd

        target = await UdpTransportTarget.create((self.address, self.port), timeout=self.timeout, retries=1)
        out = {}
        async for err, status, _, binds in bulk_walk_cmd(SnmpEngine(), self._auth(), target, ContextData(), 0, 25,
                                                         ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
            if err or status:
                raise DeviceConnectionError(f"SNMPv3 walk error: {err or status.prettyPrint()}")
            for n, v in binds:
                out[str(n)[len(oid) + 1:]] = v
        return out

    def get(self, *oids):
        return asyncio.run(self._get(oids))

    def walk(self, oid):
        return asyncio.run(self._walk(oid))

    def system(self) -> dict:
        r = self.get(OID["sysDescr"], OID["sysName"], OID["sysUpTime"])
        return {"sysDescr": str(r[OID["sysDescr"]]), "sysName": str(r[OID["sysName"]]), "uptime_hours": round(int(r[OID["sysUpTime"]]) / 360000, 2)}

    def interfaces(self) -> list[dict]:
        names = self.walk(OID["ifName"]) or self.walk(OID["ifDescr"])
        oper = self.walk(OID["ifOperStatus"])
        admin = self.walk(OID["ifAdminStatus"])
        alias = self.walk(OID["ifAlias"])
        speed = self.walk(OID["ifHighSpeed"])
        inn, outt = self.walk(OID["ifHCInOctets"]), self.walk(OID["ifHCOutOctets"])
        st = {1: "up", 2: "down", 3: "testing", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
        return [{"index": int(i), "name": str(n), "alias": str(alias.get(i, "")), "oper": st.get(int(oper.get(i, 0)), "unknown"),
                 "admin": st.get(int(admin.get(i, 0)), "unknown"), "speed_mbps": int(speed.get(i, 0) or 0),
                 "in_octets": int(inn.get(i, 0) or 0), "out_octets": int(outt.get(i, 0) or 0)} for i, n in names.items()]

    def host_resources(self) -> dict[str, float]:
        m: dict[str, float] = {}
        try:
            loads = [int(v) for v in self.walk(OID["hrProcessorLoad"]).values()]
            if loads:
                m["cpu_pct"] = round(sum(loads) / len(loads), 2)
            types = self.walk(OID["hrStorageType"])
            size, used = self.walk(OID["hrStorageSize"]), self.walk(OID["hrStorageUsed"])
            disk_max = 0.0
            for i, t in types.items():
                s, u = int(size.get(i, 0) or 0), int(used.get(i, 0) or 0)
                if not s:
                    continue
                pct = 100.0 * u / s
                if str(t).endswith(HR_RAM.split(".", 1)[1]) or str(t) == HR_RAM:
                    m["mem_pct"] = round(pct, 2)
                elif str(t).endswith(HR_DISK.split(".", 1)[1]) or str(t) == HR_DISK:
                    disk_max = max(disk_max, pct)
            if disk_max:
                m["disk_pct"] = round(disk_max, 2)
        except DeviceConnectionError:
            pass
        return m


class SnmpGenericDriver(Driver):
    key = "snmp_generic"
    category = "network"
    display_name = "Generic SNMPv3 device (monitoring only)"
    vendor = "Generic"
    device_types = ("access_point", "storage", "switch", "router", "firewall", "other")
    credential_kinds = ("snmpv3",)

    def _snmp(self) -> SnmpV3Client:
        cred = self.snmp_cred or self.cred
        if not cred or cred.get("kind") != "snmpv3":
            raise Unsupported("An SNMPv3 credential is required for this device")
        return SnmpV3Client(self.device.address, cred, self.device.port or 161)

    def test_connection(self) -> ConnectivityResult:
        t0 = time.monotonic()
        s = self._snmp().system()
        return ConnectivityResult(True, f"SNMPv3 OK: {s['sysDescr'][:80]}", (time.monotonic() - t0) * 1000, {"hostname": s["sysName"]})

    def collect_metrics(self) -> dict[str, float]:
        c = self._snmp()
        m = c.host_resources()
        m["uptime_hours"] = c.system()["uptime_hours"]
        return m

    @operation("network.snmp.system", "SNMP system info", risk="read")
    def system(self, p):
        d = self._snmp().system()
        return OpResult(data=d, output=str(d))

    @operation("network.interfaces", "Interfaces (SNMP)", risk="read")
    def interfaces(self, p):
        rows = self._snmp().interfaces()
        return OpResult(data=rows, output=f"{len(rows)} interfaces")
