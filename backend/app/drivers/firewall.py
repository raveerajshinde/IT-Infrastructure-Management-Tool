"""Firewall drivers: Fortinet FortiGate (REST API) and Sophos Firewall / XGS (XML API).

The two vendors expose very different capabilities; each driver declares only what its
API actually supports. Notably:
* FortiGate: full config backup, policy CRUD, VIP/NAT, monitor endpoints, memory/disk logs.
* Sophos XML API: object Get/Set/Remove for rules, NAT and hosts; there is NO log retrieval
  and NO full-configuration export over the API. Backup produces an object snapshot of the
  API-visible entities and is labelled as such; logs must be collected via syslog.
"""
from __future__ import annotations

import difflib

import base64

import json
import time
import xml.etree.ElementTree as ET
from typing import Literal
from xml.sax.saxutils import escape

import httpx
from pydantic import Field

from app.core.errors import DeviceConnectionError, Unsupported
from app.drivers import validators as v
from app.drivers.base import ScriptRunP, render_cli, require_library_body, ConnectivityResult, Driver, OpResult, StrictParams, operation, tls_hint


# ---------------------------------------------------------------- rule analysis (vendor neutral)
ANY_ADDR = {"all", "any", "0.0.0.0/0", "0.0.0.0 0.0.0.0", "any4", "any6"}
ANY_SVC = {"all", "any", "always"}


def analyse_rules(rules: list[dict]) -> list[dict]:
    """rules: normalised dicts {id,name,action,enabled,src:[..],dst:[..],service:[..],src_zone,dst_zone,log}"""
    findings = []
    for r in rules:
        if not r.get("enabled", True) or str(r.get("action", "")).lower() not in ("accept", "allow"):
            continue
        src_any = any(str(x).lower() in ANY_ADDR for x in r.get("src", [])) or not r.get("src")
        dst_any = any(str(x).lower() in ANY_ADDR for x in r.get("dst", [])) or not r.get("dst")
        svc_any = any(str(x).lower() in ANY_SVC for x in r.get("service", [])) or not r.get("service")
        n_any = sum([src_any, dst_any, svc_any])
        if n_any == 0:
            continue
        severity = "critical" if n_any == 3 else ("high" if n_any == 2 else "medium")
        if n_any >= 1 and str(r.get("src_zone", "")).lower() in ("wan", "untrust", "internet") and dst_any:
            severity = "critical"
        issues = [k for k, b in (("source=ANY", src_any), ("destination=ANY", dst_any), ("service=ANY", svc_any)) if b]
        findings.append({"rule_id": r.get("id"), "rule_name": r.get("name"), "severity": severity, "issues": issues,
                         "logging": r.get("log"), "recommendation": "Restrict " + ", ".join(i.split("=")[0] for i in issues) +
                         " to the specific objects required" + ("" if r.get("log") else "; enable logging on this rule")})
    order = {"critical": 0, "high": 1, "medium": 2}
    return sorted(findings, key=lambda f: order[f["severity"]])


# ---------------------------------------------------------------- params
class PolicyIdP(StrictParams):
    policy_id: int = Field(ge=1, le=10_000_000)


class PolicyToggleP(StrictParams):
    policy_id: int = Field(ge=1)
    enabled: bool


class FortiPolicyCreateP(StrictParams):
    name: v.ObjectName
    srcintf: list[v.ObjectName] = Field(min_length=1, max_length=10)
    dstintf: list[v.ObjectName] = Field(min_length=1, max_length=10)
    srcaddr: list[v.ObjectName] = Field(min_length=1, max_length=50)
    dstaddr: list[v.ObjectName] = Field(min_length=1, max_length=50)
    service: list[v.ObjectName] = Field(min_length=1, max_length=50)
    action: Literal["accept", "deny"] = "accept"
    nat: bool = False
    logtraffic: Literal["all", "utm", "disable"] = "all"
    comments: v.FreeLabel = ""
    vdom: v.ObjectName = "root"


class FortiAddressP(StrictParams):
    name: v.ObjectName
    subnet: v.Cidr | v.IPv4
    comment: v.FreeLabel = ""
    vdom: v.ObjectName = "root"


class FortiVipP(StrictParams):
    name: v.ObjectName
    extintf: v.ObjectName
    extip: v.IPv4
    mappedip: v.IPv4
    portforward: bool = False
    protocol: Literal["tcp", "udp"] = "tcp"
    extport: v.Port | None = None
    mappedport: v.Port | None = None
    vdom: v.ObjectName = "root"


class LogsP(StrictParams):
    category: Literal["traffic/forward", "event/system", "event/vpn", "utm/ips", "utm/virus", "utm/webfilter"] = "traffic/forward"
    source: Literal["memory", "disk", "fortianalyzer"] = "memory"
    rows: int = Field(100, ge=1, le=1000)


class VdomP(StrictParams):
    vdom: v.ObjectName = "root"


# ====================================================================== FortiGate

def _strip_volatile(cfg: str) -> str:
    """Drop lines FortiOS changes on every export (header timestamp, encrypted secrets re-salted)."""
    return "\n".join(ln for ln in cfg.splitlines() if not ln.startswith("#conf_file_ver") and not ln.startswith("#buildno")
                      and " ENC " not in ln)


class FortiGateDriver(Driver):
    key = "fortigate"
    category = "firewall"
    display_name = "Fortinet FortiGate (REST API)"
    vendor = "Fortinet"
    device_types = ("firewall",)
    credential_kinds = ("api_token",)
    default_port = 443

    _client: httpx.Client | None = None

    def _http(self) -> httpx.Client:
        if self._client is None:
            token = self.cred.get("token") or self.cred.get("password")
            if not token:
                raise DeviceConnectionError("FortiGate requires a REST API admin token credential")
            self._client = httpx.Client(base_url=f"https://{self.device.address}:{self.port}", verify=self.device.verify_tls,
                                        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                                        timeout=self.timeout)
        return self._client

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def _req(self, method: str, path: str, *, params: dict | None = None, body: dict | None = None, raw: bool = False):
        try:
            r = self._http().request(method, f"/api/v2/{path}", params=params, json=body)
        except httpx.HTTPError as exc:
            raise DeviceConnectionError(tls_hint(f"FortiGate API unreachable: {exc}")) from exc
        if r.status_code in (401, 403):
            raise DeviceConnectionError(f"FortiGate API denied access ({r.status_code}): check token, trusted hosts and admin profile")
        if r.status_code == 404:
            raise Unsupported(f"FortiGate API endpoint not available on this firmware: {path}")
        if r.status_code >= 400:
            raise RuntimeError(f"FortiGate API error {r.status_code}: {r.text[:500]}")
        if raw:
            return r.text
        return r.json()

    def test_connection(self) -> ConnectivityResult:
        t0 = time.monotonic()
        facts = self.collect_facts()
        return ConnectivityResult(True, f"FortiOS {facts.get('os_version', '')} API OK", (time.monotonic() - t0) * 1000, facts)

    def collect_facts(self) -> dict:
        st = self._req("GET", "monitor/system/status")
        res = st.get("results", {})
        return {"vendor": "Fortinet", "os_name": "FortiOS", "os_version": st.get("version", ""), "firmware": f"{st.get('version', '')} build {st.get('build', '')}",
                "serial_number": st.get("serial", ""), "model": res.get("model_name", res.get("model", "")), "hostname": res.get("hostname", "")}

    def collect_metrics(self) -> dict[str, float]:
        d = self._req("GET", "monitor/system/resource/usage", params={"resource": "cpu,mem,disk", "interval": "1-min"})
        out = {}
        for k, name in (("cpu", "cpu_pct"), ("mem", "mem_pct"), ("disk", "disk_pct")):
            try:
                out[name] = float(d["results"][k][0]["current"])
            except (KeyError, IndexError, TypeError):
                pass
        return out

    def _list(self, path: str, vdom: str = "root"):
        return self._req("GET", path, params={"vdom": vdom}).get("results", [])

    @operation("firewall.interfaces", "Interfaces", risk="read", params=VdomP)
    def interfaces(self, p: VdomP):
        rows = [{"name": i.get("name"), "ip": i.get("ip"), "type": i.get("type"), "status": i.get("status"), "role": i.get("role"),
                 "allowaccess": i.get("allowaccess"), "vdom": i.get("vdom")} for i in self._list("cmdb/system/interface", p.vdom)]
        return OpResult(data=rows, output=json.dumps(rows, indent=1))

    @operation("firewall.zones", "Zones", risk="read", params=VdomP)
    def zones(self, p: VdomP):
        rows = self._list("cmdb/system/zone", p.vdom)
        return OpResult(data=rows, output=json.dumps(rows, indent=1))

    @operation("firewall.routes", "Routing table", risk="read", params=VdomP)
    def routes(self, p: VdomP):
        rows = self._list("monitor/router/ipv4", p.vdom)
        return OpResult(data=rows, output=json.dumps(rows, indent=1)[:200000])

    @operation("firewall.vpn.status", "VPN status", risk="read", params=VdomP)
    def vpn(self, p: VdomP):
        ipsec = self._list("monitor/vpn/ipsec", p.vdom)
        rows = [{"name": t.get("name"), "remote": t.get("rgwy"), "incoming_bytes": t.get("incoming_bytes"),
                 "outgoing_bytes": t.get("outgoing_bytes"),
                 "phase2": [{"name": s.get("name"), "status": s.get("status")} for s in t.get("proxyid", [])]} for t in ipsec]
        try:
            ssl = self._list("monitor/vpn/ssl", p.vdom)
        except Unsupported:
            ssl = []
        return OpResult(data={"ipsec": rows, "ssl_sessions": len(ssl)}, output=json.dumps(rows, indent=1))

    def _norm_policies(self, raw: list[dict]) -> list[dict]:
        names = lambda lst: [x.get("name") for x in (lst or [])]  # noqa: E731
        return [{"id": r.get("policyid"), "name": r.get("name", ""), "action": r.get("action"), "enabled": r.get("status") == "enable",
                 "src_zone": ",".join(names(r.get("srcintf"))), "dst_zone": ",".join(names(r.get("dstintf"))),
                 "src": names(r.get("srcaddr")), "dst": names(r.get("dstaddr")), "service": names(r.get("service")),
                 "nat": r.get("nat") == "enable", "log": r.get("logtraffic") in ("all", "utm"), "comments": r.get("comments", "")}
                for r in raw]

    @operation("firewall.rules.list", "Firewall policies", risk="read", params=VdomP)
    def rules(self, p: VdomP):
        rows = self._norm_policies(self._list("cmdb/firewall/policy", p.vdom))
        return OpResult(data=rows, output=f"{len(rows)} policies")

    @operation("firewall.rules.analyse", "Analyse policies for ANY rules", risk="read", params=VdomP)
    def analyse(self, p: VdomP):
        rows = self._norm_policies(self._list("cmdb/firewall/policy", p.vdom))
        f = analyse_rules(rows)
        return OpResult(data={"findings": f, "rules_checked": len(rows)}, output=f"{len(f)} overly broad rule(s) out of {len(rows)}")

    @operation("firewall.nat.list", "NAT (VIPs and IP pools)", risk="read", params=VdomP)
    def nat(self, p: VdomP):
        data = {"vips": self._list("cmdb/firewall/vip", p.vdom), "ippools": self._list("cmdb/firewall/ippool", p.vdom)}
        return OpResult(data=data, output=f"{len(data['vips'])} VIPs, {len(data['ippools'])} IP pools")

    @operation("firewall.objects.list", "Address and service objects", risk="read", params=VdomP)
    def objects(self, p: VdomP):
        data = {"addresses": self._list("cmdb/firewall/address", p.vdom), "addrgrp": self._list("cmdb/firewall/addrgrp", p.vdom),
                "services": self._list("cmdb/firewall.service/custom", p.vdom)}
        return OpResult(data=data, output=f"{len(data['addresses'])} addresses, {len(data['services'])} services")

    @operation("firewall.logs", "Security/traffic logs", risk="read", params=LogsP)
    def logs(self, p: LogsP):
        d = self._req("GET", f"log/{p.source}/{p.category}", params={"rows": p.rows})
        rows = d.get("results", [])
        return OpResult(data=rows, output=f"{len(rows)} log entries from {p.source}")

    def _backup_text(self) -> str:
        return self._req("GET", "monitor/system/config/backup", params={"scope": "global"}, raw=True)

    @operation("firewall.config.backup", "Back up configuration", risk="read")
    def backup(self, p):
        cfg = self._backup_text()
        if not cfg.lstrip().startswith("#config-version"):
            raise RuntimeError("Unexpected backup response (not a FortiOS configuration)")
        return OpResult(output=f"Full configuration captured ({len(cfg)} bytes)", config_backups=[("full", cfg)])

    # -------------------------------------------------------------- library scripts
    @operation("firewall.script.run", "Run library FortiGate CLI script", risk="change", params=ScriptRunP, check_mode=True,
               changes="Upload and run the reviewed FortiOS CLI script from the library",
               description="Uses the FortiOS configuration-script API (System > Advanced > Configuration Scripts). FortiOS does not return "
                           "the CLI output through the API, so the result is verified by comparing the configuration before and after.")
    def script_run(self, p: ScriptRunP, check_mode=False):
        require_library_body(p)
        lines = render_cli(p.body, p.values)
        text = "\n".join(lines) + "\n"
        if check_mode:
            return OpResult(output="[check mode] FortiOS CLI script that would be uploaded and run:\n" + text)
        before = self._backup_text()
        name = f"infrapilot-{p.script_id}-{int(time.time())}.txt"
        resp = self._req("POST", "monitor/system/config-script/upload",
                         body={"filename": name, "file_content": base64.b64encode(text.encode()).decode()})
        time.sleep(3)  # the appliance applies the script asynchronously
        after = self._backup_text()
        changed = _strip_volatile(before) != _strip_volatile(after)
        ok = isinstance(resp, dict) and resp.get("status", "success") == "success"
        diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), "before", "after", n=1))
        return OpResult(status="succeeded" if ok else "failed", output=f"Uploaded and ran {name}\n\nConfiguration changes:\n{diff[:100000] or '(none)'}",
                        before=before, after=after,
                        verification=("configuration changed as a result of the script" if changed else
                                      "NO configuration change detected - check the FortiGate's configuration script log (System > Advanced)"),
                        rollback="Restore the 'full' configuration captured before the change (Config backups) or re-apply the previous lines",
                        config_backups=[("full-before", before), ("full", after)])

    def _change(self, fn, rollback: str, verify) -> OpResult:
        before = self._backup_text()
        result = fn()
        after = self._backup_text()
        ok, ver = verify()
        return OpResult(status="succeeded" if ok else "failed", output=json.dumps(result, indent=1)[:20000], before=before, after=after,
                        verification=ver, rollback=rollback, config_backups=[("full-before", before), ("full", after)])

    @operation("firewall.rule.set_enabled", "Enable/disable policy", risk="critical", params=PolicyToggleP, changes="Set firewall policy {policy_id} enabled={enabled}")
    def rule_toggle(self, p: PolicyToggleP):
        status = "enable" if p.enabled else "disable"

        def verify():
            cur = self._req("GET", f"cmdb/firewall/policy/{p.policy_id}")["results"][0]["status"]
            return cur == status, f"policy {p.policy_id} status = {cur}"
        return self._change(lambda: self._req("PUT", f"cmdb/firewall/policy/{p.policy_id}", body={"status": status}),
                            f"PUT /api/v2/cmdb/firewall/policy/{p.policy_id} {{\"status\": \"{'disable' if p.enabled else 'enable'}\"}}", verify)

    @operation("firewall.rule.create", "Create policy", risk="critical", params=FortiPolicyCreateP,
               changes="Create policy '{name}': {srcintf}->{dstintf}, {srcaddr}->{dstaddr}, services {service}, action {action}, NAT {nat}")
    def rule_create(self, p: FortiPolicyCreateP):
        body = {"name": p.name, "srcintf": [{"name": x} for x in p.srcintf], "dstintf": [{"name": x} for x in p.dstintf],
                "srcaddr": [{"name": x} for x in p.srcaddr], "dstaddr": [{"name": x} for x in p.dstaddr],
                "service": [{"name": x} for x in p.service], "action": p.action, "schedule": "always",
                "nat": "enable" if p.nat else "disable", "logtraffic": p.logtraffic, "comments": p.comments or "Created by InfraPilot", "status": "enable"}
        created = {}

        def do():
            r = self._req("POST", "cmdb/firewall/policy", params={"vdom": p.vdom}, body=body)
            created["id"] = r.get("mkey")
            return r

        def verify():
            pid = created.get("id")
            if not pid:
                return False, "API did not return the new policy id"
            cur = self._req("GET", f"cmdb/firewall/policy/{pid}", params={"vdom": p.vdom})["results"]
            return bool(cur), f"policy {pid} exists (note: new policies are appended at the end of the sequence)"
        res = self._change(do, "", verify)
        res.rollback = f"DELETE /api/v2/cmdb/firewall/policy/{created.get('id')}?vdom={p.vdom}  (or restore the 'full-before' backup)"
        return res

    @operation("firewall.rule.delete", "Delete policy", risk="critical", params=PolicyIdP, changes="Delete firewall policy {policy_id}")
    def rule_delete(self, p: PolicyIdP):
        def verify():
            try:
                self._req("GET", f"cmdb/firewall/policy/{p.policy_id}")
                return False, "policy still exists"
            except Unsupported:
                return True, "policy no longer exists"
        return self._change(lambda: self._req("DELETE", f"cmdb/firewall/policy/{p.policy_id}"),
                            "Restore from the 'full-before' configuration backup (policy definition is contained there)", verify)

    @operation("firewall.object.address.create", "Create address object", risk="change", params=FortiAddressP, changes="Create address '{name}' = {subnet}")
    def addr_create(self, p: FortiAddressP):
        subnet = p.subnet if "/" in p.subnet else f"{p.subnet}/32"
        r = self._req("POST", "cmdb/firewall/address", params={"vdom": p.vdom}, body={"name": p.name, "subnet": subnet, "comment": p.comment})
        return OpResult(output=json.dumps(r), rollback=f"DELETE /api/v2/cmdb/firewall/address/{p.name}")

    @operation("firewall.nat.vip.create", "Create VIP (destination NAT)", risk="critical", params=FortiVipP,
               changes="Create VIP '{name}' {extip}:{extport} on {extintf} -> {mappedip}:{mappedport}")
    def vip_create(self, p: FortiVipP):
        body = {"name": p.name, "extintf": p.extintf, "extip": p.extip, "mappedip": [{"range": p.mappedip}]}
        if p.portforward:
            if not (p.extport and p.mappedport):
                raise ValueError("extport and mappedport are required for port forwarding")
            body.update(portforward="enable", protocol=p.protocol, extport=str(p.extport), mappedport=str(p.mappedport))

        def verify():
            cur = self._req("GET", f"cmdb/firewall/vip/{p.name}", params={"vdom": p.vdom})["results"]
            return bool(cur), "VIP exists (a policy referencing it is still required to pass traffic)"
        return self._change(lambda: self._req("POST", "cmdb/firewall/vip", params={"vdom": p.vdom}, body=body),
                            f"DELETE /api/v2/cmdb/firewall/vip/{p.name}?vdom={p.vdom}", verify)


# ====================================================================== Sophos Firewall (SFOS / XGS)
class SophosRuleToggleP(StrictParams):
    rule_name: v.FreeLabel = Field(min_length=1)
    enabled: bool


SOPHOS_SNAPSHOT_ENTITIES = ["Zone", "Interface", "VLAN", "IPHost", "IPHostGroup", "Services", "FirewallRule", "NATRule",
                            "VPNIPSecConnection", "UnicastRoute", "DNS"]


class SophosXGSDriver(Driver):
    key = "sophos_xgs"
    category = "firewall"
    display_name = "Sophos Firewall / XGS (XML API)"
    vendor = "Sophos"
    device_types = ("firewall",)
    credential_kinds = ("password",)
    default_port = 4444

    _client: httpx.Client | None = None

    def _http(self):
        if self._client is None:
            self._client = httpx.Client(base_url=f"https://{self.device.address}:{self.port}", verify=self.device.verify_tls, timeout=self.timeout)
        return self._client

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def _login_xml(self) -> str:
        return (f"<Login><Username>{escape(self.cred.get('username') or '')}</Username>"
                f"<Password>{escape(self.cred.get('password') or '')}</Password></Login>")

    def _call(self, inner: str) -> ET.Element:
        req = f"<Request APIVersion=\"1905.1\">{self._login_xml()}{inner}</Request>"
        try:
            r = self._http().post("/webconsole/APIController", data={"reqxml": req})
        except httpx.HTTPError as exc:
            raise DeviceConnectionError(tls_hint(f"Sophos API unreachable: {exc}")) from exc
        if r.status_code >= 400:
            raise RuntimeError(f"Sophos API HTTP {r.status_code}")
        root = ET.fromstring(r.text)
        login = root.find("Login/status")
        if login is not None and "success" not in (login.text or "").lower():
            raise DeviceConnectionError(f"Sophos API login failed: {login.text}. Ensure API access is enabled and this server's IP is allowed.")
        st = root.find("Status")
        if st is not None and st.get("code") not in (None, "200", "216"):
            raise RuntimeError(f"Sophos API error {st.get('code')}: {st.text}")
        return root

    def _get(self, entity: str) -> list[ET.Element]:
        root = self._call(f"<Get><{entity}/></Get>")
        return root.findall(entity)

    @staticmethod
    def _to_dict(el: ET.Element):
        if len(el) == 0:
            return el.text
        d: dict = {}
        for c in el:
            val = SophosXGSDriver._to_dict(c)
            if c.tag in d:
                if not isinstance(d[c.tag], list):
                    d[c.tag] = [d[c.tag]]
                d[c.tag].append(val)
            else:
                d[c.tag] = val
        return d

    def test_connection(self) -> ConnectivityResult:
        t0 = time.monotonic()
        self._get("Zone")
        return ConnectivityResult(True, "Sophos XML API login OK", (time.monotonic() - t0) * 1000, {"vendor": "Sophos", "os_name": "SFOS"})

    def collect_facts(self) -> dict:
        return {"vendor": "Sophos", "os_name": "SFOS"}

    def _norm_rules(self) -> list[dict]:
        out = []
        for el in self._get("FirewallRule"):
            d = self._to_dict(el) or {}
            pol = d.get("NetworkPolicy") or d.get("UserPolicy") or {}

            def lst(node, key):
                x = (node or {}).get(key)
                if x is None:
                    return []
                if isinstance(x, dict):
                    vals = list(x.values())[0]
                    return vals if isinstance(vals, list) else [vals]
                return [x]
            out.append({"id": d.get("Position") or d.get("Name"), "name": d.get("Name"), "enabled": d.get("Status") == "Enable",
                        "action": (pol.get("Action") or "").lower(), "src_zone": ",".join(lst(pol, "SourceZones")),
                        "dst_zone": ",".join(lst(pol, "DestinationZones")), "src": lst(pol, "SourceNetworks") or ["Any"],
                        "dst": lst(pol, "DestinationNetworks") or ["Any"], "service": lst(pol, "Services") or ["Any"],
                        "log": pol.get("LogTraffic") == "Enable"})
        return out

    @operation("firewall.interfaces", "Interfaces", risk="read")
    def interfaces(self, p):
        rows = [self._to_dict(e) for e in self._get("Interface")]
        return OpResult(data=rows, output=f"{len(rows)} interfaces")

    @operation("firewall.zones", "Zones", risk="read")
    def zones(self, p):
        rows = [self._to_dict(e) for e in self._get("Zone")]
        return OpResult(data=rows, output=f"{len(rows)} zones")

    @operation("firewall.routes", "Static routes", risk="read")
    def routes(self, p):
        rows = [self._to_dict(e) for e in self._get("UnicastRoute")]
        return OpResult(data=rows, output=f"{len(rows)} static routes (dynamic routing table is not exposed by the XML API)")

    @operation("firewall.vpn.status", "IPsec VPN connections", risk="read")
    def vpn(self, p):
        rows = [self._to_dict(e) for e in self._get("VPNIPSecConnection")]
        return OpResult(data=rows, output=f"{len(rows)} IPsec connections (configuration view; live tunnel state is not exposed by the XML API)")

    @operation("firewall.rules.list", "Firewall rules", risk="read")
    def rules(self, p):
        rows = self._norm_rules()
        return OpResult(data=rows, output=f"{len(rows)} rules")

    @operation("firewall.rules.analyse", "Analyse rules for ANY", risk="read")
    def analyse(self, p):
        rows = self._norm_rules()
        f = analyse_rules(rows)
        return OpResult(data={"findings": f, "rules_checked": len(rows)}, output=f"{len(f)} overly broad rule(s) out of {len(rows)}")

    @operation("firewall.nat.list", "NAT rules", risk="read")
    def nat(self, p):
        rows = [self._to_dict(e) for e in self._get("NATRule")]
        return OpResult(data=rows, output=f"{len(rows)} NAT rules")

    @operation("firewall.objects.list", "Host and service objects", risk="read")
    def objects(self, p):
        data = {"hosts": [self._to_dict(e) for e in self._get("IPHost")], "services": [self._to_dict(e) for e in self._get("Services")]}
        return OpResult(data=data, output=f"{len(data['hosts'])} hosts, {len(data['services'])} services")

    def _snapshot(self) -> str:
        parts = []
        for ent in SOPHOS_SNAPSHOT_ENTITIES:
            try:
                for el in self._get(ent):
                    parts.append(ET.tostring(el, encoding="unicode"))
            except RuntimeError:
                continue
        return "<!-- InfraPilot Sophos API object snapshot (not a restorable SFOS backup) -->\n<Snapshot>\n" + "\n".join(parts) + "\n</Snapshot>\n"

    @operation("firewall.config.backup", "API object snapshot", risk="read",
               description="Captures API-visible objects (zones, interfaces, rules, NAT, hosts, services, VPN). Full SFOS backups must be scheduled on the appliance.")
    def backup(self, p):
        snap = self._snapshot()
        return OpResult(output=f"Object snapshot captured ({len(snap)} bytes). Note: not a full appliance backup.", config_backups=[("api-snapshot", snap)])

    @operation("firewall.rule.set_enabled", "Enable/disable rule", risk="critical", params=SophosRuleToggleP, changes="Set firewall rule '{rule_name}' enabled={enabled}")
    def rule_toggle(self, p: SophosRuleToggleP):
        target = None
        for el in self._get("FirewallRule"):
            if (el.findtext("Name") or "") == p.rule_name:
                target = el
                break
        if target is None:
            return OpResult(status="failed", output=f"Rule '{p.rule_name}' not found")
        before = self._snapshot()
        st = target.find("Status")
        old = st.text if st is not None else None
        if st is None:
            st = ET.SubElement(target, "Status")
        st.text = "Enable" if p.enabled else "Disable"
        self._call(f"<Set operation=\"update\">{ET.tostring(target, encoding='unicode')}</Set>")
        cur = next((e.findtext("Status") for e in self._get("FirewallRule") if e.findtext("Name") == p.rule_name), None)
        ok = cur == st.text
        after = self._snapshot()
        return OpResult(status="succeeded" if ok else "failed", output=f"Rule '{p.rule_name}': {old} -> {cur}", before=before, after=after,
                        verification=f"Status reported by API: {cur}", rollback=f"Set rule '{p.rule_name}' Status back to {old}",
                        config_backups=[("api-snapshot-before", before), ("api-snapshot", after)])
