"""Virtualization drivers: Proxmox VE (REST API token) and VMware vCenter (vSphere Automation REST)."""
from __future__ import annotations

import json
import time
from typing import Literal

import httpx
from pydantic import Field

from app.core.errors import DeviceConnectionError, Unsupported
from app.drivers.base import ConnectivityResult, Driver, OpResult, StrictParams, operation, tls_hint


class PveVmP(StrictParams):
    node: str = Field(pattern=r"^[A-Za-z0-9\-_.]{1,63}$")
    vmid: int = Field(ge=100, le=999_999_999)
    type: Literal["qemu", "lxc"] = "qemu"


class PveActionP(PveVmP):
    action: Literal["start", "shutdown", "stop", "reboot", "suspend", "resume"]


class PveSnapListP(PveVmP):
    pass


class PveSnapP(PveVmP):
    snapname: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_\-]{1,39}$", description="Letters, digits, - and _; must start with a letter")
    description: str = Field("Created by InfraPilot", max_length=200)
    vmstate: bool = Field(False, description="Include RAM state (QEMU only)")


class PveSnapNameP(PveVmP):
    snapname: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_\-]{1,39}$")


class VcVmActionP(StrictParams):
    vm: str = Field(pattern=r"^vm-\d+$")
    action: Literal["start", "stop", "reset", "suspend", "guest-shutdown", "guest-reboot"]


def _pct(used, total) -> float | None:
    try:
        return round(100.0 * float(used) / float(total), 2) if total else None
    except (TypeError, ValueError):
        return None


class ProxmoxDriver(Driver):
    key = "proxmox"
    category = "virtualization"
    display_name = "Proxmox VE"
    vendor = "Proxmox"
    device_types = ("hypervisor",)
    credential_kinds = ("api_token",)
    default_port = 8006
    _client: httpx.Client | None = None

    def _http(self):
        if self._client is None:
            tid, secret = self.cred.get("username"), self.cred.get("token") or self.cred.get("password")
            if not tid or not secret or "!" not in tid:
                raise DeviceConnectionError("Proxmox requires an API token credential: username 'user@realm!tokenid', secret = token UUID")
            self._client = httpx.Client(base_url=f"https://{self.device.address}:{self.port}/api2/json", verify=self.device.verify_tls,
                                        headers={"Authorization": f"PVEAPIToken={tid}={secret}"}, timeout=self.timeout)
        return self._client

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def _req(self, method, path, **kw):
        try:
            r = self._http().request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise DeviceConnectionError(tls_hint(f"Proxmox API unreachable: {exc}")) from exc
        if r.status_code == 401:
            raise DeviceConnectionError("Proxmox API token rejected")
        if r.status_code == 403:
            raise RuntimeError(f"Proxmox API permission denied for {path} (check token privileges)")
        if r.status_code >= 400:
            raise RuntimeError(f"Proxmox API error {r.status_code}: {r.text[:300]}")
        return r.json().get("data")

    def test_connection(self) -> ConnectivityResult:
        t0 = time.monotonic()
        v = self._req("GET", "/version")
        return ConnectivityResult(True, f"Proxmox VE {v.get('version')} API OK", (time.monotonic() - t0) * 1000,
                                  {"vendor": "Proxmox", "os_name": "Proxmox VE", "os_version": v.get("version", "")})

    def collect_facts(self) -> dict:
        v = self._req("GET", "/version")
        return {"vendor": "Proxmox", "os_name": "Proxmox VE", "os_version": v.get("version", ""), "firmware": v.get("release", "")}

    def collect_metrics(self) -> dict[str, float]:
        nodes = self._req("GET", "/nodes") or []
        if not nodes:
            return {}
        cpu = sum(n.get("cpu", 0) for n in nodes) / len(nodes) * 100
        mem = _pct(sum(n.get("mem", 0) for n in nodes), sum(n.get("maxmem", 0) for n in nodes))
        disk = _pct(sum(n.get("disk", 0) for n in nodes), sum(n.get("maxdisk", 0) for n in nodes))
        return {k: round(val, 2) for k, val in {"cpu_pct": cpu, "mem_pct": mem, "disk_pct": disk}.items() if val is not None}

    @operation("virt.hosts", "Nodes", risk="read")
    def hosts(self, p):
        rows = [{"node": n.get("node"), "status": n.get("status"), "cpu_pct": round(n.get("cpu", 0) * 100, 1),
                 "mem_pct": _pct(n.get("mem"), n.get("maxmem")), "uptime_h": round(n.get("uptime", 0) / 3600, 1)} for n in self._req("GET", "/nodes")]
        return OpResult(data=rows, output=json.dumps(rows, indent=1))

    @operation("virt.vms", "Virtual machines and containers", risk="read")
    def vms(self, p):
        rows = [{"vmid": r.get("vmid"), "name": r.get("name"), "type": r.get("type"), "node": r.get("node"), "status": r.get("status"),
                 "cpu_pct": round((r.get("cpu") or 0) * 100, 1), "mem_pct": _pct(r.get("mem"), r.get("maxmem")),
                 "maxmem_gb": round((r.get("maxmem") or 0) / 2**30, 1), "uptime_h": round((r.get("uptime") or 0) / 3600, 1)}
                for r in self._req("GET", "/cluster/resources", params={"type": "vm"})]
        return OpResult(data=rows, output=f"{len(rows)} guests")

    @operation("virt.storage", "Storage", risk="read")
    def storage(self, p):
        rows = [{"storage": r.get("storage"), "node": r.get("node"), "status": r.get("status"), "used_pct": _pct(r.get("disk"), r.get("maxdisk")),
                 "size_gb": round((r.get("maxdisk") or 0) / 2**30, 1), "plugin": r.get("plugintype")}
                for r in self._req("GET", "/cluster/resources", params={"type": "storage"})]
        return OpResult(data=rows, output=f"{len(rows)} storages")

    @operation("virt.backups", "Backup jobs and recent vzdump tasks", risk="read")
    def backups(self, p):
        jobs = self._req("GET", "/cluster/backup") or []
        tasks = []
        for n in self._req("GET", "/nodes") or []:
            for t in self._req("GET", f"/nodes/{n['node']}/tasks", params={"typefilter": "vzdump", "limit": 20}) or []:
                tasks.append({"node": n["node"], "id": t.get("id"), "status": t.get("status"), "start": t.get("starttime"), "end": t.get("endtime")})
        return OpResult(data={"jobs": jobs, "recent": tasks}, output=f"{len(jobs)} scheduled jobs, {len(tasks)} recent runs")

    @operation("virt.vm.power", "VM power action", risk="critical", params=PveActionP, changes="{action} {type} guest {vmid} on node {node}")
    def vm_power(self, p: PveActionP):
        base = f"/nodes/{p.node}/{p.type}/{p.vmid}/status"
        before = self._req("GET", f"{base}/current")
        upid = self._req("POST", f"{base}/{p.action}")
        deadline = time.time() + min(self.timeout * 3, 300)
        status = None
        while time.time() < deadline:
            t = self._req("GET", f"/nodes/{p.node}/tasks/{upid}/status")
            if t.get("status") == "stopped":
                status = t.get("exitstatus")
                break
            time.sleep(2)
        after = self._req("GET", f"{base}/current")
        return OpResult(status="succeeded" if status == "OK" else "failed", output=f"Task {upid}: {status or 'timeout'}",
                        before=json.dumps({"status": before.get("status")}), after=json.dumps({"status": after.get("status")}),
                        verification=f"guest status now {after.get('status')}", rollback=f"Return guest to '{before.get('status')}' state")

    def _wait_task(self, node: str, upid: str) -> str | None:
        deadline = time.time() + min(self.timeout * 5, 900)
        while time.time() < deadline:
            t = self._req("GET", f"/nodes/{node}/tasks/{upid}/status")
            if t.get("status") == "stopped":
                return t.get("exitstatus")
            time.sleep(2)
        return None

    def _snaps(self, p) -> list[dict]:
        return [s for s in (self._req("GET", f"/nodes/{p.node}/{p.type}/{p.vmid}/snapshot") or []) if s.get("name") != "current"]

    @operation("virt.vm.snapshots", "List guest snapshots", risk="read", params=PveSnapListP)
    def vm_snapshots(self, p: PveSnapListP):
        rows = [{"snapname": s.get("name"), "description": (s.get("description") or "").strip(), "parent": s.get("parent"),
                 "created": time.strftime("%Y-%m-%d %H:%M", time.gmtime(s["snaptime"])) if s.get("snaptime") else "", "vmstate": bool(s.get("vmstate"))}
                for s in self._snaps(p)]
        return OpResult(data=rows, output=f"{len(rows)} snapshot(s)")

    @operation("virt.vm.snapshot.create", "Create guest snapshot", risk="change", params=PveSnapP,
               changes="Create snapshot '{snapname}' of {type} guest {vmid} on {node}")
    def vm_snapshot_create(self, p: PveSnapP):
        body = {"snapname": p.snapname, "description": p.description}
        if p.type == "qemu" and p.vmstate:
            body["vmstate"] = 1
        upid = self._req("POST", f"/nodes/{p.node}/{p.type}/{p.vmid}/snapshot", data=body)
        status = self._wait_task(p.node, upid)
        present = any(s.get("name") == p.snapname for s in self._snaps(p))
        return OpResult(status="succeeded" if status == "OK" and present else "failed", output=f"Task {upid}: {status or 'timeout'}",
                        verification=f"snapshot {'present' if present else 'NOT found'}", rollback=f"Delete snapshot '{p.snapname}'")

    @operation("virt.vm.snapshot.rollback", "Roll back guest to snapshot", risk="critical", params=PveSnapNameP,
               changes="Revert {type} guest {vmid} on {node} to snapshot '{snapname}' (current state is lost)")
    def vm_snapshot_rollback(self, p: PveSnapNameP):
        upid = self._req("POST", f"/nodes/{p.node}/{p.type}/{p.vmid}/snapshot/{p.snapname}/rollback")
        status = self._wait_task(p.node, upid)
        return OpResult(status="succeeded" if status == "OK" else "failed", output=f"Task {upid}: {status or 'timeout'}",
                        verification=f"rollback task {status or 'timeout'}", rollback="Not reversible: take a snapshot first if the current state matters")

    @operation("virt.vm.snapshot.delete", "Delete guest snapshot", risk="critical", params=PveSnapNameP,
               changes="Delete snapshot '{snapname}' of {type} guest {vmid} on {node}")
    def vm_snapshot_delete(self, p: PveSnapNameP):
        upid = self._req("DELETE", f"/nodes/{p.node}/{p.type}/{p.vmid}/snapshot/{p.snapname}")
        status = self._wait_task(p.node, upid)
        gone = not any(s.get("name") == p.snapname for s in self._snaps(p))
        return OpResult(status="succeeded" if status == "OK" and gone else "failed", output=f"Task {upid}: {status or 'timeout'}",
                        verification=f"snapshot {'removed' if gone else 'still present'}", rollback="Not reversible")


class VMwareDriver(Driver):
    key = "vmware_vcenter"
    category = "virtualization"
    display_name = "VMware vCenter (REST)"
    vendor = "VMware"
    device_types = ("hypervisor",)
    credential_kinds = ("password",)
    default_port = 443
    _client: httpx.Client | None = None

    def _http(self):
        if self._client is None:
            c = httpx.Client(base_url=f"https://{self.device.address}:{self.port}", verify=self.device.verify_tls, timeout=self.timeout)
            try:
                r = c.post("/api/session", auth=(self.cred.get("username") or "", self.cred.get("password") or ""))
            except httpx.HTTPError as exc:
                raise DeviceConnectionError(tls_hint(f"vCenter unreachable: {exc}")) from exc
            if r.status_code == 404:
                raise Unsupported("vCenter REST /api endpoints require vSphere 7.0U2 or later")
            if r.status_code != 201:
                raise DeviceConnectionError(f"vCenter login failed ({r.status_code})")
            c.headers["vmware-api-session-id"] = r.json()
            self._client = c
        return self._client

    def close(self):
        if self._client:
            try:
                self._client.delete("/api/session")
            except Exception:
                pass
            self._client.close()
            self._client = None

    def _get(self, path, **kw):
        r = self._http().get(path, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"vCenter API error {r.status_code}: {r.text[:300]}")
        return r.json()

    def test_connection(self) -> ConnectivityResult:
        t0 = time.monotonic()
        facts = self.collect_facts()
        return ConnectivityResult(True, f"vCenter {facts.get('os_version', '')} API OK", (time.monotonic() - t0) * 1000, facts)

    def collect_facts(self) -> dict:
        v = self._get("/api/appliance/system/version")
        return {"vendor": "VMware", "os_name": v.get("product", "vCenter"), "os_version": v.get("version", ""), "firmware": v.get("build", "")}

    def collect_metrics(self) -> dict[str, float]:
        ds = self._get("/api/vcenter/datastore")
        tot = sum(d.get("capacity", 0) for d in ds)
        free = sum(d.get("free_space", 0) for d in ds)
        return {"disk_pct": round(100 * (1 - free / tot), 2)} if tot else {}

    @operation("virt.hosts", "ESXi hosts", risk="read")
    def hosts(self, p):
        rows = self._get("/api/vcenter/host")
        return OpResult(data=rows, output=f"{len(rows)} hosts")

    @operation("virt.vms", "Virtual machines", risk="read")
    def vms(self, p):
        rows = self._get("/api/vcenter/vm")
        return OpResult(data=rows, output=f"{len(rows)} VMs")

    @operation("virt.storage", "Datastores", risk="read")
    def storage(self, p):
        rows = [{**d, "used_pct": _pct((d.get("capacity") or 0) - (d.get("free_space") or 0), d.get("capacity"))} for d in self._get("/api/vcenter/datastore")]
        return OpResult(data=rows, output=f"{len(rows)} datastores")

    @operation("virt.vm.power", "VM power action", risk="critical", params=VcVmActionP, changes="{action} VM {vm}")
    def vm_power(self, p: VcVmActionP):
        before = self._get(f"/api/vcenter/vm/{p.vm}/power")
        if p.action.startswith("guest-"):
            r = self._http().post(f"/api/vcenter/vm/{p.vm}/guest/power", params={"action": p.action.split("-", 1)[1]})
        else:
            r = self._http().post(f"/api/vcenter/vm/{p.vm}/power", params={"action": p.action})
        if r.status_code >= 400:
            return OpResult(status="failed", output=f"vCenter rejected action ({r.status_code}): {r.text[:500]}")
        time.sleep(3)
        after = self._get(f"/api/vcenter/vm/{p.vm}/power")
        return OpResult(output=f"{p.vm}: {before.get('state')} -> {after.get('state')}", before=json.dumps(before), after=json.dumps(after),
                        verification=f"power state {after.get('state')} (guest actions complete asynchronously)",
                        rollback=f"Return VM to {before.get('state')}")
