"""Network discovery: ICMP sweep + management-port fingerprinting to suggest a platform."""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import socket

from app.drivers.snmp import ping, tcp_check

PORT_HINTS = {
    5986: ("windows_server", "windows"), 5985: ("windows_server", "windows"), 8006: ("hypervisor", "proxmox"),
    4444: ("firewall", "sophos_xgs"), 22: ("linux_server", "linux"), 443: ("other", None),
}


def _probe(ip: str, ports: list[int]) -> dict | None:
    up, rtt = ping(ip, count=1, timeout=1)
    open_ports = [p for p in ports if tcp_check(ip, p, timeout=0.8)[0]]
    if not up and not open_ports:
        return None
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        name = ""
    dtype, platform = "other", None
    for p in (5986, 5985, 8006, 4444, 22, 443):
        if p in open_ports:
            dtype, platform = PORT_HINTS[p]
            break
    port = None
    if platform == "windows":  # WinRM: prefer HTTPS when its listener exists, otherwise the default HTTP listener
        port = 5986 if 5986 in open_ports else 5985
    return {"ip_address": ip, "hostname": name.split(".")[0] if name else "", "fqdn": name, "icmp": up, "rtt_ms": rtt,
            "open_ports": open_ports, "suggested_device_type": dtype, "suggested_platform": platform, "suggested_port": port,
            "note": "Port 22 alone may also indicate a network device; confirm the platform before registering." if platform == "linux" else ""}


def sweep(cidr: str, ports: list[int]) -> list[dict]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
    ports = [p for p in ports if 1 <= p <= 65535][:10]
    with cf.ThreadPoolExecutor(max_workers=64) as ex:
        found = [r for r in ex.map(lambda h: _probe(h, ports), hosts) if r]
    return sorted(found, key=lambda r: ipaddress.ip_address(r["ip_address"]))
