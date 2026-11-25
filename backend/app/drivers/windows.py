"""Windows Server driver (WinRM/PSRP via pypsrp).

Every operation runs a fixed PowerShell script whose inputs are bound through the PSRP
parameter mechanism (AddParameter), never string-concatenated into code, so parameter
values cannot inject PowerShell. Scripts emit JSON which the driver parses.

Role-dependent operations (AD, DNS, DHCP, GPO, IIS) check that the required module is
present on the target and raise a clear UNSUPPORTED error instead of failing obscurely.
Run them against a domain controller / role server, or a management server with RSAT.
"""
from __future__ import annotations

import json
import re
import time
from typing import Literal

from pydantic import Field

from app.core.errors import DeviceConnectionError, Unsupported, ValidationFailed
from app.drivers import validators as v
from app.drivers.base import ScriptRunP, require_library_body, ConnectivityResult, Driver, OpResult, StrictParams, operation, tls_hint

PRELUDE = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; $WarningPreference='SilentlyContinue'\n"


def need_module(name: str, hint: str) -> str:
    return (f"if (-not (Get-Module -ListAvailable -Name {name})) "
            f"{{ throw 'UNSUPPORTED: PowerShell module {name} is not available on this host ({hint})' }}\n"
            f"Import-Module {name}\n")


def ps(param_block: str, body: str) -> str:
    """Compose a script: param() block, strict prelude, body; result serialised as JSON."""
    return (f"param({param_block})\n{PRELUDE}"
            f"$__r = @(& {{\n{body}\n}})\n"
            "ConvertTo-Json -InputObject $__r -Depth 6 -Compress")

_PS_TYPE = {"int": "[long]", "bool": "[bool]", "vlan": "[int]"}


def script_with_params(defs: list[dict], body: str) -> str:
    """Declare the library parameters so values are bound by PSRP (never spliced into the script text)."""
    decl = ", ".join(f"{_PS_TYPE.get(d['type'], '[string]')}${d['name']}" for d in defs)
    return (f"param({decl})\n$ErrorActionPreference = 'Stop'\n"
            f"& {{\n{body}\n}} 2>&1 | ForEach-Object {{ if ($_ -is [System.Management.Automation.ErrorRecord]) {{ \"ERROR: $_\" }} else {{ $_ }} }} "
            f"| Out-String -Width 250 -Stream")


SVC_SELECT = ("Select-Object Name,DisplayName,@{n='Status';e={$_.Status.ToString()}},"
              "@{n='StartType';e={$_.StartType.ToString()}}")


# ---------------------------------------------------------------- parameter models
class ServiceP(StrictParams):
    name: v.ServiceName


class ServiceListP(StrictParams):
    name_filter: v.ServiceName | None = None


class FeatureP(StrictParams):
    name: v.FeatureName
    include_management_tools: bool = True
    restart: bool = False


class FolderP(StrictParams):
    path: v.WinPath


class ShareCreateP(StrictParams):
    name: v.ShareName
    path: v.WinPath
    description: v.FreeLabel = ""
    full_access: list[v.Principal] = Field(default_factory=list, max_length=20)
    change_access: list[v.Principal] = Field(default_factory=list, max_length=20)
    read_access: list[v.Principal] = Field(default_factory=lambda: [], max_length=20)
    create_folder: bool = True


class ShareP(StrictParams):
    name: v.ShareName


class SharePermP(StrictParams):
    name: v.ShareName
    principal: v.Principal
    access: Literal["Full", "Change", "Read"]


class NtfsGetP(StrictParams):
    path: v.WinPath


class NtfsGrantP(StrictParams):
    path: v.WinPath
    principal: v.Principal
    rights: Literal["FullControl", "Modify", "ReadAndExecute", "Read", "Write", "ListDirectory"]
    access_type: Literal["Allow", "Deny"] = "Allow"
    inherit: bool = True


class LocalUserCreateP(StrictParams):
    username: v.AccountName
    full_name: v.FreeLabel = ""
    description: v.FreeLabel = ""
    password: str = Field(min_length=12, max_length=128)
    groups: list[v.Principal] = Field(default_factory=list, max_length=10)


class LocalUserP(StrictParams):
    username: v.AccountName


class LocalGroupMemberP(StrictParams):
    group: v.Principal
    member: v.Principal


class EventsP(StrictParams):
    log_name: Literal["System", "Application", "Security", "Setup", "Microsoft-Windows-GroupPolicy/Operational",
                      "Directory Service", "DNS Server", "Microsoft-Windows-TaskScheduler/Operational"] = "System"
    level: Literal["any", "critical", "error", "warning", "information"] = "any"
    hours: int = Field(24, ge=1, le=720)
    max_events: int = Field(100, ge=1, le=1000)


class TaskP(StrictParams):
    task_name: v.TaskName
    task_path: v.TaskPath = "\\"


class FwRuleCreateP(StrictParams):
    display_name: v.FreeLabel = Field(min_length=3)
    direction: Literal["Inbound", "Outbound"] = "Inbound"
    action: Literal["Allow", "Block"] = "Allow"
    protocol: Literal["TCP", "UDP"] = "TCP"
    local_port: list[v.Port] = Field(min_length=1, max_length=20)
    remote_address: list[v.IPv4 | v.Cidr] = Field(default_factory=list, max_length=50)
    profile: Literal["Any", "Domain", "Private", "Public"] = "Domain"


class FwRuleListP(StrictParams):
    name_filter: v.FreeLabel = Field("", description="Part of the rule display name")
    include_disabled: bool = False
    direction: Literal["Any", "Inbound", "Outbound"] = "Inbound"


class FwRuleUpdateP(StrictParams):
    display_name: v.FreeLabel = Field(min_length=1)
    action: Literal["", "Allow", "Block"] = Field("", description="Leave empty to keep")
    local_port: list[v.Port] = Field(default_factory=list, max_length=20, description="Leave empty to keep (TCP/UDP rules only)")
    remote_address: list[v.IPv4 | v.Cidr] = Field(default_factory=list, max_length=50, description="Leave empty to keep")
    any_remote_address: bool = Field(False, description="Reset remote address to Any")
    profile: Literal["", "Any", "Domain", "Private", "Public"] = Field("", description="Leave empty to keep")


class FwRuleNameP(StrictParams):
    display_name: v.FreeLabel = Field(min_length=1)


class FwRuleToggleP(StrictParams):
    display_name: v.FreeLabel = Field(min_length=1)
    enabled: bool


class IisSiteP(StrictParams):
    name: v.ObjectName


class IisPoolP(StrictParams):
    name: v.ObjectName


class AdUserListP(StrictParams):
    search: v.AccountName | None = None
    search_base: v.DistinguishedName | None = None
    max_results: int = Field(200, ge=1, le=2000)


class AdUserCreateP(StrictParams):
    sam_account_name: v.AccountName
    given_name: v.FreeLabel = ""
    surname: v.FreeLabel = ""
    display_name: v.FreeLabel = ""
    user_principal_name: str = Field(pattern=r"^[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+$")
    ou: v.DistinguishedName
    password: str = Field(min_length=12, max_length=128)
    enabled: bool = True
    change_password_at_logon: bool = True


class AdUserP(StrictParams):
    sam_account_name: v.AccountName


class AdUserEnableP(StrictParams):
    sam_account_name: v.AccountName
    enabled: bool


class AdResetPwP(StrictParams):
    sam_account_name: v.AccountName
    new_password: str = Field(min_length=12, max_length=128)
    change_password_at_logon: bool = True


class AdGroupListP(StrictParams):
    search: v.AccountName | None = None


class AdGroupMemberP(StrictParams):
    group: v.Principal
    member: v.AccountName


class AdOuCreateP(StrictParams):
    name: v.ObjectName
    parent_dn: v.DistinguishedName
    protect_from_deletion: bool = True


class DnsZoneP(StrictParams):
    zone: v.DnsName


class DnsRecordAddP(StrictParams):
    zone: v.DnsName
    name: v.DnsName
    type: Literal["A", "CNAME"]
    value: str = Field(max_length=253, pattern=r"^[A-Za-z0-9.\-_]+$")
    ttl_seconds: int = Field(3600, ge=60, le=86400)


class DnsRecordRemoveP(StrictParams):
    zone: v.DnsName
    name: v.DnsName
    type: Literal["A", "CNAME"]


class DhcpScopeP(StrictParams):
    scope_id: v.IPv4


class DhcpReservationP(StrictParams):
    scope_id: v.IPv4
    ip_address: v.IPv4
    client_id: v.Mac
    name: v.FreeLabel = ""


class GpoP(StrictParams):
    name: v.GpoName


class GpoCreateP(StrictParams):
    name: v.GpoName
    comment: v.FreeLabel = ""


class GpoLinkP(StrictParams):
    name: v.GpoName
    target_dn: v.DistinguishedName
    enforced: bool = False
    link_enabled: bool = True


class GpoReportP(StrictParams):
    name: v.GpoName
    report_type: Literal["Html", "Xml"] = "Html"


class GpoRegistryP(StrictParams):
    name: v.GpoName
    key: v.RegistryKey
    value_name: str = Field(pattern=r"^[A-Za-z0-9 _.\-]{1,128}$")
    value_type: Literal["String", "DWord", "ExpandString", "QWord"]
    value: str = Field(max_length=500, pattern=r"^[^\x00-\x1f]*$")


class GpoCollectP(StrictParams):
    domain: v.DnsName | None = None


class GpoRsopP(StrictParams):
    computer: v.DnsName | None = Field(None, description="Computer to report on (default: this server)")
    user: str | None = Field(None, pattern=r"^[A-Za-z0-9._-]{1,64}\\[A-Za-z0-9._ $-]{1,104}$", description="DOMAIN\\user (optional; default is the account InfraPilot connects with)")


class GpoBackupP(StrictParams):
    name: v.GpoName
    path: v.WinPath = Field(description="Folder on this server (or its share path) that holds GPO backups, e.g. D:\\GPOBackups")
    comment: v.FreeLabel = ""


class GpoBackupListP(StrictParams):
    path: v.WinPath


class GpoRestoreP(StrictParams):
    name: v.GpoName
    path: v.WinPath
    backup_id: str = Field(pattern=r"^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$")


class GpUpdateP(StrictParams):
    computer: v.DnsName | None = None
    force: bool = True


class CertListP(StrictParams):
    store: Literal["My", "Root", "CA", "WebHosting"] = "My"
    expiring_within_days: int | None = Field(None, ge=1, le=3650)


class RebootP(StrictParams):
    delay_seconds: int = Field(60, ge=0, le=3600)
    reason: v.FreeLabel = Field("Planned maintenance (InfraPilot)", min_length=3)


class ProcListP(StrictParams):
    sort_by: Literal["cpu", "memory"] = "cpu"
    limit: int = Field(30, ge=1, le=200)


class ProcStopP(StrictParams):
    pid: int = Field(ge=5, le=4_294_967_295)
    force: bool = False


class SoftwareP(StrictParams):
    name_filter: v.FreeLabel = ""


# ---------------------------------------------------------------- driver
class WindowsDriver(Driver):
    key = "windows"
    category = "windows"
    display_name = "Windows Server (WinRM/PSRP)"
    vendor = "Microsoft"
    device_types = ("windows_server", "workstation")
    credential_kinds = ("password", "winrm")
    default_port = 5986

    _pool = None
    _client = None

    # -------------------------------------------------------------- library scripts
    @operation("windows.script.run", "Run library PowerShell script", risk="change", params=ScriptRunP, check_mode=True,
               changes="Run the reviewed PowerShell script from the library")
    def script_run(self, p: ScriptRunP, check_mode=False):
        require_library_body(p)
        full = script_with_params(p.param_defs, p.body)
        bound = "\n".join(f"  ${k} = {v!r}" for k, v in p.values.items()) or "  (no parameters)"
        if check_mode:
            return OpResult(output=f"[check mode] would run '{p.name}' with:\n{bound}\n\n{p.body}")
        from pypsrp.powershell import PowerShell
        shell = PowerShell(self._connect())
        shell.add_script(full)
        if p.values:
            shell.add_parameters({k: val for k, val in p.values.items() if val is not None and val != ""})
        out = shell.invoke()
        text = "\n".join(str(o) for o in out if o is not None).rstrip()
        errors = [str(e) for e in shell.streams.error]
        failed = shell.had_errors or any(ln.startswith("ERROR: ") for ln in text.splitlines())
        return OpResult(status="failed" if failed else "succeeded", output=(text + ("\n" + "\n".join(errors) if errors else ""))[:200000] or "(no output)",
                        verification="script completed without errors" if not failed else "script reported errors",
                        rollback="Use the script's own rollback procedure (documented in its description)")

    # -------------------------------------------------------------- transport
    def winrm_endpoint(self) -> tuple[bool, int]:
        """Decide HTTP vs HTTPS. The credential's explicit 'use_ssl' wins; otherwise the device port decides
        (5985 = HTTP, anything else = HTTPS). A default port that contradicts the protocol is corrected."""
        explicit = self.cred.get("use_ssl")
        if isinstance(explicit, str):
            explicit = explicit.strip().lower() in ("1", "true", "yes", "on")
        port = int(self.port or self.default_port)
        use_ssl = bool(explicit) if explicit is not None else port != 5985
        if use_ssl and port == 5985:
            port = 5986
        elif not use_ssl and port == 5986:
            port = 5985
        return use_ssl, port

    def _connect(self):
        if self._pool is not None:
            return self._pool
        from pypsrp.powershell import RunspacePool
        from pypsrp.wsman import WSMan

        transport = self.cred.get("transport", "negotiate")  # negotiate | kerberos | ntlm | credssp | basic
        use_ssl, port = self.winrm_endpoint()
        if not use_ssl and transport == "basic":
            raise DeviceConnectionError("Basic authentication over WinRM HTTP would send the password in clear text. "
                                        "Use Negotiate/NTLM/Kerberos (encrypted over HTTP) or switch the device to HTTPS (5986).")
        try:
            wsman = WSMan(
                self.device.address, port=port, ssl=use_ssl,
                username=self.cred.get("username"), password=self.cred.get("password"), auth=transport,
                cert_validation=self.device.verify_tls, connection_timeout=min(self.timeout, 30),
                operation_timeout=max(self.timeout - 5, 20), read_timeout=self.timeout + 10,
                # Over HTTP, Negotiate/NTLM/Kerberos/CredSSP encrypt every message, so commands and output are not sent in clear text.
                encryption="always" if not use_ssl else "auto",
            )
            self._pool = RunspacePool(wsman)
            self._pool.open()
        except Exception as exc:
            self._pool = None
            msg = tls_hint(f"WinRM ({'HTTPS' if use_ssl else 'HTTP'} {port}) connection to {self.device.address} failed: {exc}")
            if use_ssl and msg.endswith("button under the failed test)."):
                msg += " Servers without a WinRM certificate can also be managed over HTTP: edit the device and choose WinRM over HTTP (port 5985)."
            raise DeviceConnectionError(msg) from exc
        return self._pool

    def _invoke(self, script: str, params: dict | None = None):
        from pypsrp.powershell import PowerShell

        pool = self._connect()
        shell = PowerShell(pool)
        shell.add_script(script)
        if params:
            shell.add_parameters({k: val for k, val in params.items() if val is not None})
        out = shell.invoke()
        if shell.had_errors:
            msg = "; ".join(str(e) for e in shell.streams.error) or "PowerShell reported an error"
            if "UNSUPPORTED:" in msg:
                raise Unsupported(msg.split("UNSUPPORTED:", 1)[1].strip())
            raise RuntimeError(msg)
        text = "\n".join(str(o) for o in out if o is not None).strip()
        if not text:
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def close(self):
        if self._pool is not None:
            try:
                self._pool.close()
            except Exception:
                pass
            self._pool = None

    def _ok(self, data, output: str = "", **kw) -> OpResult:
        return OpResult(status="succeeded", data=data, output=output or json.dumps(data, indent=2, default=str)[:200000], **kw)

    # -------------------------------------------------------------- lifecycle
    def test_connection(self) -> ConnectivityResult:
        t0 = time.monotonic()
        facts = self.collect_facts()
        use_ssl, port = self.winrm_endpoint()
        proto = f"HTTPS {port}" if use_ssl else f"HTTP {port}, message-encrypted"
        return ConnectivityResult(True, f"WinRM OK ({proto}) - {facts.get('os_name', '')}", (time.monotonic() - t0) * 1000, facts)

    def collect_facts(self) -> dict:
        r = self._invoke(ps("", """
$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem; $bios = Get-CimInstance Win32_BIOS
[pscustomobject]@{ hostname=$env:COMPUTERNAME; os_name=$os.Caption; os_version=$os.Version; vendor=$cs.Manufacturer;
  model=$cs.Model; serial_number=$bios.SerialNumber; firmware=$bios.SMBIOSBIOSVersion; domain=$cs.Domain }"""))
        return r[0] if isinstance(r, list) and r else {}

    def collect_metrics(self) -> dict[str, float]:
        r = self._invoke(ps("", """
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$os = Get-CimInstance Win32_OperatingSystem
$mem = 100 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100)
$d = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { 100 - ($_.FreeSpace / $_.Size * 100) } | Measure-Object -Maximum
[pscustomobject]@{ cpu_pct=[double]$cpu; mem_pct=[double]$mem; disk_pct=[double]$d.Maximum;
  uptime_hours=[double]((Get-Date) - $os.LastBootUpTime).TotalHours }"""))
        row = r[0] if isinstance(r, list) and r else {}
        return {k: round(float(val), 2) for k, val in row.items() if val is not None}

    # -------------------------------------------------------------- system
    @operation("windows.system.info", "System information", risk="read")
    def system_info(self, p):
        data = self._invoke(ps("", """
$os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
$pend = (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') -or
        (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')
[pscustomobject]@{ Hostname=$env:COMPUTERNAME; Domain=$cs.Domain; OS=$os.Caption; Build=$os.BuildNumber; Version=$os.Version;
  LastBoot=$os.LastBootUpTime; UptimeHours=[math]::Round(((Get-Date)-$os.LastBootUpTime).TotalHours,1);
  CPUs=$cs.NumberOfLogicalProcessors; MemoryGB=[math]::Round($cs.TotalPhysicalMemory/1GB,1); RebootPending=[bool]$pend;
  TimeZone=(Get-TimeZone).Id; Manufacturer=$cs.Manufacturer; Model=$cs.Model }"""))
        return self._ok(data[0] if data else {})

    @operation("windows.system.reboot", "Restart server", risk="critical", params=RebootP,
               changes="Restart {delay_seconds}s after the request (reason: {reason}); users are disconnected")
    def system_reboot(self, p: RebootP):
        self._invoke(ps("[int]$Delay,[string]$Reason", "shutdown.exe /r /t $Delay /c $Reason /d p:4:1 | Out-Null; [pscustomobject]@{ Scheduled=$true }"),
                     {"Delay": p.delay_seconds, "Reason": p.reason})
        return OpResult(output=f"Restart scheduled in {p.delay_seconds}s", verification="Use Test connectivity after the restart to confirm the server is back",
                        rollback=f"Before it happens: shutdown.exe /a (abort) on {self.device.hostname}")

    @operation("windows.processes.list", "Processes", risk="read", params=ProcListP)
    def processes(self, p: ProcListP):
        key = "CPU" if p.sort_by == "cpu" else "WorkingSet64"
        data = self._invoke(ps("[string]$Key,[int]$Limit", """Get-Process | Sort-Object -Property $Key -Descending | Select-Object -First $Limit Id,ProcessName,
 @{n='CPUSeconds';e={[math]::Round($_.CPU,1)}},@{n='MemoryMB';e={[math]::Round($_.WorkingSet64/1MB,1)}},@{n='StartTime';e={$_.StartTime}}"""),
            {"Key": key, "Limit": p.limit})
        return self._ok(data)

    @operation("windows.process.stop", "Stop process", risk="change", params=ProcStopP, changes="Stop process {pid} (force={force})")
    def process_stop(self, p: ProcStopP):
        before = self._invoke(ps("[int]$Id", "Get-Process -Id $Id | Select-Object Id,ProcessName"), {"Id": p.pid})
        self._invoke(ps("[int]$Id,[bool]$Force", "Stop-Process -Id $Id -Force:$Force -Confirm:$false"), {"Id": p.pid, "Force": p.force})
        gone = self._invoke(ps("[int]$Id", "[pscustomobject]@{ Running = [bool](Get-Process -Id $Id -ErrorAction SilentlyContinue) }"), {"Id": p.pid})
        ok = not gone[0]["Running"]
        return OpResult(status="succeeded" if ok else "failed", output=f"Process {p.pid} ({before[0]['ProcessName']}) {'stopped' if ok else 'still running'}",
                        before=json.dumps(before), verification=f"Running = {not ok}", rollback=f"Restart the application/service that owned {before[0]['ProcessName']}")

    @operation("windows.updates.pending", "Pending Windows updates", risk="read")
    def updates_pending(self, p):
        data = self._invoke(ps("", """
$s = New-Object -ComObject Microsoft.Update.Session; $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
@($r.Updates | ForEach-Object { [pscustomobject]@{ Title=$_.Title; KB=($_.KBArticleIDs -join ','); Severity=$_.MsrcSeverity;
  SizeMB=[math]::Round($_.MaxDownloadSize/1MB,1); RebootRequired=$_.RebootRequired } })"""))
        return self._ok(data, output=f"{len(data)} pending update(s)")

    @operation("windows.software.list", "Installed software", risk="read", params=SoftwareP)
    def software(self, p: SoftwareP):
        data = self._invoke(ps("[string]$Filter", """
$keys = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and (-not $Filter -or $_.DisplayName -like "*$Filter*") } |
 Sort-Object DisplayName -Unique | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate"""), {"Filter": p.name_filter})
        return self._ok(data)

    @operation("windows.network.config", "Network configuration", risk="read")
    def network_config(self, p):
        data = self._invoke(ps("", """Get-NetIPConfiguration | ForEach-Object { [pscustomobject]@{ Interface=$_.InterfaceAlias;
 IPv4=@($_.IPv4Address | % IPAddress) -join ', '; Gateway=@($_.IPv4DefaultGateway | % NextHop) -join ', ';
 DNS=@($_.DNSServer | Where-Object AddressFamily -eq 2 | % ServerAddresses) -join ', '; Status=$_.NetAdapter.Status } }"""))
        return self._ok(data)

    # -------------------------------------------------------------- services
    @operation("windows.services.list", "List services", risk="read", params=ServiceListP)
    def services_list(self, p: ServiceListP):
        data = self._invoke(ps("[string]$Name", f"if ($Name) {{ Get-Service -Name $Name | {SVC_SELECT} }} else {{ Get-Service | {SVC_SELECT} }}"),
                            {"Name": p.name_filter})
        return self._ok(data)

    def _svc_action(self, p: ServiceP, verb: str, expect: str, check_mode: bool) -> OpResult:
        get = ps("[string]$Name", f"Get-Service -Name $Name | {SVC_SELECT}")
        before = self._invoke(get, {"Name": p.name})
        if check_mode:
            return OpResult(status="succeeded", output=f"[check mode] Would {verb.lower()} service '{p.name}' (currently {before[0]['Status']}).",
                            before=json.dumps(before))
        self._invoke(ps("[string]$Name", f"{verb}-Service -Name $Name -Confirm:$false" + (" -Force" if verb != "Start" else "")), {"Name": p.name})
        after = self._invoke(ps("[string]$Name", f"(Get-Service -Name $Name).WaitForStatus('{expect}', [TimeSpan]::FromSeconds(30)); Get-Service -Name $Name | {SVC_SELECT}"), {"Name": p.name})
        ok = after and after[0].get("Status") == expect
        return OpResult(status="succeeded" if ok else "failed", output=f"Service {p.name}: {before[0]['Status']} -> {after[0]['Status']}",
                        before=json.dumps(before), after=json.dumps(after),
                        verification=f"Status is {after[0]['Status']} (expected {expect})",
                        rollback=f"Restore previous state: service was {before[0]['Status']}.")

    @operation("windows.service.inspect", "Inspect service", risk="read", params=ServiceP)
    def service_inspect(self, p: ServiceP):
        data = self._invoke(ps("[string]$Name", """
$s = Get-CimInstance Win32_Service -Filter "Name='$($Name -replace "'","''")'"
if (-not $s) { throw "Service $Name not found" }
$svc = Get-Service -Name $Name
[pscustomobject]@{ Name=$s.Name; DisplayName=$s.DisplayName; State=$s.State; StartMode=$s.StartMode; Account=$s.StartName;
  Path=$s.PathName; ProcessId=$s.ProcessId; DependentServices=@($svc.DependentServices | % Name); RequiredServices=@($svc.RequiredServices | % Name) }"""),
            {"Name": p.name})
        return self._ok(data)

    @operation("windows.service.start", "Start service", risk="change", params=ServiceP, check_mode=True, changes="Start Windows service '{name}'")
    def service_start(self, p: ServiceP, check_mode=False):
        return self._svc_action(p, "Start", "Running", check_mode)

    @operation("windows.service.stop", "Stop service", risk="change", params=ServiceP, check_mode=True, changes="Stop Windows service '{name}' (dependent services are stopped too)")
    def service_stop(self, p: ServiceP, check_mode=False):
        return self._svc_action(p, "Stop", "Stopped", check_mode)

    @operation("windows.service.restart", "Restart service", risk="change", params=ServiceP, check_mode=True, changes="Restart Windows service '{name}'")
    def service_restart(self, p: ServiceP, check_mode=False):
        return self._svc_action(p, "Restart", "Running", check_mode)

    # -------------------------------------------------------------- roles & features
    @operation("windows.features.list", "List roles and features", risk="read")
    def features_list(self, p):
        data = self._invoke(ps("", need_module("ServerManager", "Windows Server only") +
                               "Get-WindowsFeature | Select-Object Name,DisplayName,Installed,@{n='InstallState';e={$_.InstallState.ToString()}},FeatureType"))
        return self._ok(data)

    @operation("windows.feature.install", "Install role/feature", risk="critical", params=FeatureP, check_mode=True,
               changes="Install Windows feature '{name}' (management tools: {include_management_tools}, restart if required: {restart})")
    def feature_install(self, p: FeatureP, check_mode=False):
        data = self._invoke(ps("[string]$Name,[bool]$Tools,[bool]$Restart,[bool]$WhatIf", need_module("ServerManager", "Windows Server only") + """
$r = Install-WindowsFeature -Name $Name -IncludeManagementTools:$Tools -Restart:$Restart -WhatIf:$WhatIf
$st = (Get-WindowsFeature -Name $Name).InstallState.ToString()
[pscustomobject]@{ Success=$r.Success; RestartNeeded=$r.RestartNeeded.ToString(); ExitCode=$r.ExitCode.ToString(); InstallState=$st }"""),
            {"Name": p.name, "Tools": p.include_management_tools, "Restart": p.restart, "WhatIf": check_mode})
        row = data[0]
        ok = bool(row.get("Success"))
        return OpResult(status="succeeded" if ok else "failed", data=data, output=json.dumps(row),
                        verification=None if check_mode else f"InstallState = {row.get('InstallState')}",
                        rollback=f"Uninstall-WindowsFeature -Name {p.name}")

    @operation("windows.feature.uninstall", "Uninstall role/feature", risk="critical", params=FeatureP, check_mode=True,
               changes="Remove Windows feature '{name}'")
    def feature_uninstall(self, p: FeatureP, check_mode=False):
        data = self._invoke(ps("[string]$Name,[bool]$Restart,[bool]$WhatIf", need_module("ServerManager", "Windows Server only") + """
$r = Uninstall-WindowsFeature -Name $Name -Restart:$Restart -WhatIf:$WhatIf
[pscustomobject]@{ Success=$r.Success; RestartNeeded=$r.RestartNeeded.ToString(); InstallState=(Get-WindowsFeature -Name $Name).InstallState.ToString() }"""),
            {"Name": p.name, "Restart": p.restart, "WhatIf": check_mode})
        ok = bool(data[0].get("Success"))
        return OpResult(status="succeeded" if ok else "failed", data=data, output=json.dumps(data[0]),
                        rollback=f"Install-WindowsFeature -Name {p.name}")

    # -------------------------------------------------------------- folders & shares
    @operation("windows.folder.create", "Create folder", risk="change", params=FolderP, check_mode=True, changes="Create folder {path}")
    def folder_create(self, p: FolderP, check_mode=False):
        data = self._invoke(ps("[string]$Path,[bool]$WhatIf", """
$exists = Test-Path -LiteralPath $Path
if (-not $exists -and -not $WhatIf) { New-Item -ItemType Directory -Path $Path | Out-Null }
[pscustomobject]@{ Path=$Path; AlreadyExisted=$exists; ExistsNow=(Test-Path -LiteralPath $Path) }"""),
            {"Path": p.path, "WhatIf": check_mode})
        row = data[0]
        return OpResult(status="succeeded", data=data,
                        output=("Folder already existed" if row["AlreadyExisted"] else ("Would create" if check_mode else "Created")) + f" {p.path}",
                        verification=None if check_mode else f"Test-Path = {row['ExistsNow']}",
                        rollback=None if row["AlreadyExisted"] else f"Remove-Item -LiteralPath '{p.path}' (only if empty)")

    @operation("windows.shares.list", "List SMB shares", risk="read")
    def shares_list(self, p):
        return self._ok(self._invoke(ps("", "Get-SmbShare | Select-Object Name,Path,Description,CurrentUsers,@{n='ShareType';e={$_.ShareType.ToString()}}")))

    @operation("windows.share.create", "Create SMB share", risk="change", params=ShareCreateP, check_mode=True,
               changes="Create SMB share '{name}' at {path} (full: {full_access}, change: {change_access}, read: {read_access})")
    def share_create(self, p: ShareCreateP, check_mode=False):
        if check_mode:
            return OpResult(output=f"[check mode] Would create share {p.name} -> {p.path}")
        data = self._invoke(ps("[string]$Name,[string]$Path,[string]$Description,[string[]]$Full,[string[]]$Change,[string[]]$Read,[bool]$CreateFolder", """
if (Get-SmbShare -Name $Name -ErrorAction SilentlyContinue) { throw "Share $Name already exists" }
if (-not (Test-Path -LiteralPath $Path)) { if ($CreateFolder) { New-Item -ItemType Directory -Path $Path | Out-Null } else { throw "Path $Path does not exist" } }
$args = @{ Name=$Name; Path=$Path; Description=$Description }
if ($Full) { $args.FullAccess = $Full }; if ($Change) { $args.ChangeAccess = $Change }; if ($Read) { $args.ReadAccess = $Read }
if (-not ($Full -or $Change -or $Read)) { $args.ReadAccess = 'Everyone' }
New-SmbShare @args | Out-Null
Get-SmbShareAccess -Name $Name | Select-Object AccountName,@{n='AccessRight';e={$_.AccessRight.ToString()}},@{n='AccessControlType';e={$_.AccessControlType.ToString()}}"""),
            {"Name": p.name, "Path": p.path, "Description": p.description, "Full": p.full_access or None,
             "Change": p.change_access or None, "Read": p.read_access or None, "CreateFolder": p.create_folder})
        return self._ok(data, after=json.dumps(data), verification="Share exists with ACL shown", rollback=f"Remove-SmbShare -Name '{p.name}' -Force")

    @operation("windows.share.remove", "Remove SMB share", risk="critical", params=ShareP, changes="Remove SMB share '{name}' (folder content is NOT deleted)")
    def share_remove(self, p: ShareP):
        before = self._invoke(ps("[string]$Name", "Get-SmbShare -Name $Name | Select-Object Name,Path,Description"), {"Name": p.name})
        self._invoke(ps("[string]$Name", "Remove-SmbShare -Name $Name -Force"), {"Name": p.name})
        return OpResult(output=f"Removed share {p.name}", before=json.dumps(before),
                        rollback=f"New-SmbShare -Name '{p.name}' -Path '{before[0]['Path']}' and re-apply permissions")

    @operation("windows.share.access.get", "Get share permissions", risk="read", params=ShareP)
    def share_access_get(self, p: ShareP):
        return self._ok(self._invoke(ps("[string]$Name", "Get-SmbShareAccess -Name $Name | Select-Object AccountName,@{n='AccessRight';e={$_.AccessRight.ToString()}},@{n='AccessControlType';e={$_.AccessControlType.ToString()}}"), {"Name": p.name}))

    @operation("windows.share.access.grant", "Grant share permission", risk="change", params=SharePermP, changes="Grant {access} on share '{name}' to {principal}")
    def share_access_grant(self, p: SharePermP):
        q = "Get-SmbShareAccess -Name $Name | Select-Object AccountName,@{n='AccessRight';e={$_.AccessRight.ToString()}}"
        before = self._invoke(ps("[string]$Name", q), {"Name": p.name})
        self._invoke(ps("[string]$Name,[string]$Account,[string]$Right", "Grant-SmbShareAccess -Name $Name -AccountName $Account -AccessRight $Right -Force | Out-Null"),
                     {"Name": p.name, "Account": p.principal, "Right": p.access})
        after = self._invoke(ps("[string]$Name", q), {"Name": p.name})
        return OpResult(output=f"Granted {p.access} to {p.principal}", before=json.dumps(before), after=json.dumps(after),
                        rollback=f"Revoke-SmbShareAccess -Name '{p.name}' -AccountName '{p.principal}' -Force")

    @operation("windows.ntfs.get", "Get NTFS permissions", risk="read", params=NtfsGetP)
    def ntfs_get(self, p: NtfsGetP):
        return self._ok(self._invoke(ps("[string]$Path", """(Get-Acl -LiteralPath $Path).Access | Select-Object IdentityReference,
 @{n='Rights';e={$_.FileSystemRights.ToString()}},@{n='Type';e={$_.AccessControlType.ToString()}},IsInherited,
 @{n='Inheritance';e={$_.InheritanceFlags.ToString()}}"""), {"Path": p.path}))

    @operation("windows.ntfs.grant", "Grant NTFS permission", risk="change", params=NtfsGrantP, check_mode=True,
               changes="{access_type} {rights} on {path} for {principal} (inherit: {inherit})")
    def ntfs_grant(self, p: NtfsGrantP, check_mode=False):
        before = self.ntfs_get(NtfsGetP(path=p.path)).data
        if check_mode:
            return OpResult(output=f"[check mode] Would add {p.access_type} {p.rights} for {p.principal} on {p.path}", before=json.dumps(before))
        self._invoke(ps("[string]$Path,[string]$Principal,[string]$Rights,[string]$Type,[bool]$Inherit", """
$acl = Get-Acl -LiteralPath $Path
$inh = if ($Inherit) { 'ContainerInherit,ObjectInherit' } else { 'None' }
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal, $Rights, $inh, 'None', $Type)
$acl.AddAccessRule($rule); Set-Acl -LiteralPath $Path -AclObject $acl"""),
            {"Path": p.path, "Principal": p.principal, "Rights": p.rights, "Type": p.access_type, "Inherit": p.inherit})
        after = self.ntfs_get(NtfsGetP(path=p.path)).data
        found = any(str(a.get("IdentityReference", "")).lower().endswith(p.principal.lower().split("\\")[-1]) for a in after)
        return OpResult(status="succeeded" if found else "failed", output=f"ACL updated on {p.path}", before=json.dumps(before), after=json.dumps(after),
                        verification="ACE present" if found else "ACE not found after change",
                        rollback=f"Remove the {p.access_type} {p.rights} ACE for {p.principal} on {p.path} (icacls \"{p.path}\" /remove \"{p.principal}\")")

    # -------------------------------------------------------------- local users / groups
    @operation("windows.localusers.list", "List local users", risk="read")
    def local_users(self, p):
        return self._ok(self._invoke(ps("", "Get-LocalUser | Select-Object Name,FullName,Enabled,LastLogon,PasswordExpires,Description")))

    @operation("windows.localgroups.list", "List local groups and members", risk="read")
    def local_groups(self, p):
        return self._ok(self._invoke(ps("", "Get-LocalGroup | ForEach-Object { [pscustomobject]@{ Name=$_.Name; Description=$_.Description; Members=@(Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue | ForEach-Object Name) } }")))

    @operation("windows.localuser.create", "Create local user", risk="change", params=LocalUserCreateP, secret_params=("password",),
               changes="Create local user '{username}' and add to groups {groups}")
    def local_user_create(self, p: LocalUserCreateP):
        data = self._invoke(ps("[string]$Name,[string]$FullName,[string]$Description,[string]$Password,[string[]]$Groups", """
$sec = ConvertTo-SecureString $Password -AsPlainText -Force
New-LocalUser -Name $Name -FullName $FullName -Description $Description -Password $sec | Out-Null
foreach ($g in $Groups) { if ($g) { Add-LocalGroupMember -Group $g -Member $Name } }
Get-LocalUser -Name $Name | Select-Object Name,Enabled,FullName"""),
            {"Name": p.username, "FullName": p.full_name, "Description": p.description, "Password": p.password, "Groups": p.groups or None})
        return self._ok(data, verification="User exists", rollback=f"Remove-LocalUser -Name '{p.username}'")

    @operation("windows.localuser.disable", "Disable local user", risk="change", params=LocalUserP, changes="Disable local user '{username}'")
    def local_user_disable(self, p: LocalUserP):
        data = self._invoke(ps("[string]$Name", "Disable-LocalUser -Name $Name; Get-LocalUser -Name $Name | Select-Object Name,Enabled"), {"Name": p.username})
        return OpResult(status="succeeded" if data and data[0]["Enabled"] is False else "failed", data=data, output=json.dumps(data),
                        rollback=f"Enable-LocalUser -Name '{p.username}'")

    @operation("windows.localgroup.add_member", "Add member to local group", risk="change", params=LocalGroupMemberP, changes="Add {member} to local group '{group}'")
    def local_group_add(self, p: LocalGroupMemberP):
        self._invoke(ps("[string]$Group,[string]$Member", "Add-LocalGroupMember -Group $Group -Member $Member"), {"Group": p.group, "Member": p.member})
        return OpResult(output=f"Added {p.member} to {p.group}", rollback=f"Remove-LocalGroupMember -Group '{p.group}' -Member '{p.member}'")

    # -------------------------------------------------------------- storage
    @operation("windows.storage.list", "List disks and volumes", risk="read")
    def storage_list(self, p):
        data = self._invoke(ps("", """
[pscustomobject]@{
 Disks = @(Get-Disk | Select-Object Number,FriendlyName,SerialNumber,@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},@{n='PartitionStyle';e={$_.PartitionStyle.ToString()}},@{n='Health';e={$_.HealthStatus.ToString()}},IsOffline)
 Volumes = @(Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter,FileSystemLabel,FileSystem,@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}},@{n='Health';e={$_.HealthStatus.ToString()}})
}"""))
        return self._ok(data[0] if data else {})

    # -------------------------------------------------------------- events
    @operation("windows.events.query", "Query Event Viewer", risk="read", params=EventsP)
    def events_query(self, p: EventsP):
        lvl = {"any": None, "critical": 1, "error": 2, "warning": 3, "information": 4}[p.level]
        data = self._invoke(ps("[string]$Log,[int]$Level,[int]$Hours,[int]$Max", """
$f = @{ LogName=$Log; StartTime=(Get-Date).AddHours(-$Hours) }
if ($Level -gt 0) { $f.Level = $Level }
try { Get-WinEvent -FilterHashtable $f -MaxEvents $Max -ErrorAction Stop | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,@{n='Message';e={ if ($_.Message) { $_.Message.Substring(0,[Math]::Min(1000,$_.Message.Length)) } }} }
catch [Exception] { if ($_.Exception.Message -match 'No events were found') { @() } else { throw } }"""),
            {"Log": p.log_name, "Level": lvl or 0, "Hours": p.hours, "Max": p.max_events})
        return self._ok(data)

    # -------------------------------------------------------------- scheduled tasks
    @operation("windows.tasks.list", "List scheduled tasks", risk="read")
    def tasks_list(self, p):
        return self._ok(self._invoke(ps("", "Get-ScheduledTask | Where-Object TaskPath -notlike '\\Microsoft\\*' | ForEach-Object { $i = $_ | Get-ScheduledTaskInfo; [pscustomobject]@{ TaskName=$_.TaskName; TaskPath=$_.TaskPath; State=$_.State.ToString(); LastRunTime=$i.LastRunTime; LastTaskResult=$i.LastTaskResult; NextRunTime=$i.NextRunTime } }")))

    def _task_action(self, p: TaskP, cmd: str, label: str) -> OpResult:
        data = self._invoke(ps("[string]$TaskName,[string]$TaskPath", f"{cmd} -TaskName $TaskName -TaskPath $TaskPath | Out-Null; Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath | Select-Object TaskName,@{{n='State';e={{$_.State.ToString()}}}}"),
                            {"TaskName": p.task_name, "TaskPath": p.task_path})
        return OpResult(output=f"{label} {p.task_path}{p.task_name}: state {data[0]['State']}", data=data, verification=f"State = {data[0]['State']}")

    @operation("windows.task.run", "Run scheduled task now", risk="change", params=TaskP, changes="Start scheduled task {task_path}{task_name} now")
    def task_run(self, p: TaskP):
        return self._task_action(p, "Start-ScheduledTask", "Started")

    @operation("windows.task.enable", "Enable scheduled task", risk="change", params=TaskP, changes="Enable scheduled task {task_path}{task_name}")
    def task_enable(self, p: TaskP):
        r = self._task_action(p, "Enable-ScheduledTask", "Enabled")
        r.rollback = f"Disable-ScheduledTask -TaskName '{p.task_name}' -TaskPath '{p.task_path}'"
        return r

    @operation("windows.task.disable", "Disable scheduled task", risk="change", params=TaskP, changes="Disable scheduled task {task_path}{task_name}")
    def task_disable(self, p: TaskP):
        r = self._task_action(p, "Disable-ScheduledTask", "Disabled")
        r.rollback = f"Enable-ScheduledTask -TaskName '{p.task_name}' -TaskPath '{p.task_path}'"
        return r

    # -------------------------------------------------------------- certificates
    @operation("windows.certs.list", "List certificates", risk="read", params=CertListP)
    def certs_list(self, p: CertListP):
        data = self._invoke(ps("[string]$Store,[int]$Days", """
$c = Get-ChildItem -Path ("Cert:\\LocalMachine\\" + $Store)
if ($Days -gt 0) { $c = $c | Where-Object { $_.NotAfter -lt (Get-Date).AddDays($Days) } }
$c | Select-Object Subject,Issuer,Thumbprint,NotBefore,NotAfter,HasPrivateKey,@{n='DaysLeft';e={[int]($_.NotAfter - (Get-Date)).TotalDays}},@{n='DnsNames';e={@($_.DnsNameList | % Unicode)}}"""),
            {"Store": p.store, "Days": p.expiring_within_days or 0})
        return self._ok(data)

    # -------------------------------------------------------------- firewall
    @operation("windows.firewall.profiles", "Firewall profiles", risk="read")
    def fw_profiles(self, p):
        return self._ok(self._invoke(ps("", "Get-NetFirewallProfile | Select-Object Name,Enabled,@{n='DefaultInboundAction';e={$_.DefaultInboundAction.ToString()}},@{n='DefaultOutboundAction';e={$_.DefaultOutboundAction.ToString()}}")))

    @operation("windows.firewall.rules.list", "List firewall rules", risk="read", params=FwRuleListP)
    def fw_rules(self, p: FwRuleListP):
        return self._ok(self._invoke(ps("[string]$Filter,[bool]$All,[string]$Dir", """
$pf = @{}; Get-NetFirewallPortFilter -All | ForEach-Object { $pf[$_.InstanceID] = $_ }
$af = @{}; Get-NetFirewallAddressFilter -All | ForEach-Object { $af[$_.InstanceID] = $_ }
$rules = Get-NetFirewallRule
if (-not $All) { $rules = $rules | Where-Object { $_.Enabled -eq 'True' } }
if ($Dir -ne 'Any') { $rules = $rules | Where-Object { $_.Direction.ToString() -eq $Dir } }
if ($Filter) { $rules = $rules | Where-Object { $_.DisplayName -like "*$Filter*" } }
$rules | Select-Object -First 500 | ForEach-Object {
  $f = $pf[$_.InstanceID]; $a = $af[$_.InstanceID]
  [pscustomobject]@{ DisplayName=$_.DisplayName; Enabled=$_.Enabled.ToString(); Direction=$_.Direction.ToString(); Action=$_.Action.ToString();
    Protocol=$f.Protocol; LocalPort=(@($f.LocalPort) -join ','); RemoteAddress=(@($a.RemoteAddress) -join ','); Profile=$_.Profile.ToString(); Group=$_.Group }
}"""), {"Filter": p.name_filter, "All": p.include_disabled, "Dir": p.direction}))

    _FW_ONE = """$r = Get-NetFirewallRule -DisplayName $Name -ErrorAction Stop | Select-Object -First 1
$f = $r | Get-NetFirewallPortFilter; $a = $r | Get-NetFirewallAddressFilter
[pscustomobject]@{ DisplayName=$r.DisplayName; Enabled=$r.Enabled.ToString(); Direction=$r.Direction.ToString(); Action=$r.Action.ToString();
  Protocol=$f.Protocol; LocalPort=(@($f.LocalPort) -join ','); RemoteAddress=(@($a.RemoteAddress) -join ','); Profile=$r.Profile.ToString(); Group=$r.Group }"""

    def _fw_guard(self, name: str) -> None:
        if re.search(r"windows remote management|winrm", name, re.I):
            raise ValidationFailed("Refusing to change WinRM firewall rules: InfraPilot manages this server through WinRM")

    @operation("windows.firewall.rule.update", "Edit firewall rule", risk="change", params=FwRuleUpdateP,
               changes="Update firewall rule '{display_name}' (action {action}, ports {local_port}, remote {remote_address}, profile {profile})")
    def fw_rule_update(self, p: FwRuleUpdateP):
        self._fw_guard(p.display_name)
        if not (p.action or p.local_port or p.remote_address or p.any_remote_address or p.profile):
            raise ValidationFailed("Nothing to change: set at least one field")
        get = ps("[string]$Name", self._FW_ONE)
        before = self._invoke(get, {"Name": p.display_name})
        self._invoke(ps("[string]$Name,[string]$Action,[string[]]$Ports,[string[]]$Remote,[bool]$AnyRemote,[string]$Profile", """
$a = @{ DisplayName=$Name }
if ($Action) { $a.Action = $Action }
if ($Ports) { $a.LocalPort = $Ports }
if ($Remote) { $a.RemoteAddress = $Remote } elseif ($AnyRemote) { $a.RemoteAddress = 'Any' }
if ($Profile) { $a.Profile = $Profile }
Set-NetFirewallRule @a -ErrorAction Stop"""), {"Name": p.display_name, "Action": p.action, "Ports": [str(x) for x in p.local_port] or None,
                                              "Remote": p.remote_address or None, "AnyRemote": p.any_remote_address, "Profile": p.profile})
        after = self._invoke(get, {"Name": p.display_name})
        b, a = (before or [{}])[0], (after or [{}])[0]
        ok = (not p.action or a.get("Action") == p.action) and (not p.local_port or a.get("LocalPort") == ",".join(map(str, p.local_port)))
        rb = f"Set-NetFirewallRule -DisplayName '{p.display_name}' -Action {b.get('Action')} -LocalPort {b.get('LocalPort') or 'Any'} -RemoteAddress {b.get('RemoteAddress') or 'Any'} -Profile {b.get('Profile')}"
        return OpResult(status="succeeded" if ok else "failed", data=after, output=json.dumps(after, indent=1), before=json.dumps(b, indent=1),
                        after=json.dumps(a, indent=1), verification="rule re-read after change: " + ("matches" if ok else "does NOT match"), rollback=rb)

    @operation("windows.firewall.rule.remove", "Delete firewall rule", risk="change", params=FwRuleNameP,
               changes="Delete firewall rule '{display_name}'")
    def fw_rule_remove(self, p: FwRuleNameP):
        self._fw_guard(p.display_name)
        get = ps("[string]$Name", self._FW_ONE)
        before = self._invoke(get, {"Name": p.display_name})
        b = (before or [{}])[0]
        self._invoke(ps("[string]$Name", "Remove-NetFirewallRule -DisplayName $Name -ErrorAction Stop"), {"Name": p.display_name})
        gone = not self._invoke(ps("[string]$Name", "Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue | Select-Object DisplayName"),
                                {"Name": p.display_name})
        rb = (f"New-NetFirewallRule -DisplayName '{b.get('DisplayName')}' -Direction {b.get('Direction')} -Action {b.get('Action')} "
              f"-Protocol {b.get('Protocol')} -LocalPort {b.get('LocalPort') or 'Any'} -RemoteAddress {b.get('RemoteAddress') or 'Any'} -Profile {b.get('Profile')}")
        return OpResult(status="succeeded" if gone else "failed", output=f"Deleted '{p.display_name}'", before=json.dumps(b, indent=1),
                        verification="rule " + ("no longer exists" if gone else "STILL exists"), rollback=rb)

    @operation("windows.firewall.rule.create", "Create firewall rule", risk="change", params=FwRuleCreateP, check_mode=True,
               changes="{action} {direction} {protocol} port(s) {local_port} from {remote_address} on profile {profile} ('{display_name}')")
    def fw_rule_create(self, p: FwRuleCreateP, check_mode=False):
        if check_mode:
            return OpResult(output=f"[check mode] Would create rule '{p.display_name}'")
        data = self._invoke(ps("[string]$Name,[string]$Direction,[string]$Action,[string]$Protocol,[string[]]$Ports,[string[]]$Remote,[string]$Profile", """
if (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue) { throw "A rule named '$Name' already exists" }
$a = @{ DisplayName=$Name; Direction=$Direction; Action=$Action; Protocol=$Protocol; LocalPort=$Ports; Profile=$Profile; Group='InfraPilot' }
if ($Remote) { $a.RemoteAddress = $Remote }
New-NetFirewallRule @a | Select-Object DisplayName,Enabled,@{n='Action';e={$_.Action.ToString()}}"""),
            {"Name": p.display_name, "Direction": p.direction, "Action": p.action, "Protocol": p.protocol,
             "Ports": [str(x) for x in p.local_port], "Remote": p.remote_address or None, "Profile": p.profile})
        return self._ok(data, rollback=f"Remove-NetFirewallRule -DisplayName '{p.display_name}'", verification="Rule created")

    @operation("windows.firewall.rule.set_enabled", "Enable/disable firewall rule", risk="change", params=FwRuleToggleP,
               changes="Set firewall rule '{display_name}' enabled={enabled}")
    def fw_rule_toggle(self, p: FwRuleToggleP):
        self._fw_guard(p.display_name)
        data = self._invoke(ps("[string]$Name,[bool]$On", "$e = if ($On) { 'True' } else { 'False' }; Set-NetFirewallRule -DisplayName $Name -Enabled $e; Get-NetFirewallRule -DisplayName $Name | Select-Object DisplayName,@{n='Enabled';e={$_.Enabled.ToString()}}"),
                            {"Name": p.display_name, "On": p.enabled})
        return self._ok(data, rollback=f"Set-NetFirewallRule -DisplayName '{p.display_name}' -Enabled {not p.enabled}")

    # -------------------------------------------------------------- IIS
    @operation("windows.iis.sites.list", "List IIS sites and app pools", risk="read")
    def iis_sites(self, p):
        return self._ok(self._invoke(ps("", need_module("WebAdministration", "IIS management scripts and tools not installed") + """
[pscustomobject]@{ Sites=@(Get-Website | Select-Object Name,ID,State,PhysicalPath,@{n='Bindings';e={@($_.bindings.Collection | % { $_.protocol + ' ' + $_.bindingInformation })}});
 AppPools=@(Get-ChildItem IIS:\\AppPools | Select-Object Name,State,managedRuntimeVersion) }""")))

    def _iis(self, cmd: str, name: str, getter: str) -> OpResult:
        data = self._invoke(ps("[string]$Name", need_module("WebAdministration", "IIS not installed") + f"{cmd} -Name $Name; Start-Sleep -Seconds 1; {getter}"), {"Name": name})
        return self._ok(data, verification=f"State: {data[0].get('State') if data else 'unknown'}")

    @operation("windows.iis.site.start", "Start IIS site", risk="change", params=IisSiteP, changes="Start IIS site '{name}'")
    def iis_site_start(self, p: IisSiteP):
        return self._iis("Start-Website", p.name, "Get-Website -Name $Name | Select-Object Name,State")

    @operation("windows.iis.site.stop", "Stop IIS site", risk="change", params=IisSiteP, changes="Stop IIS site '{name}' (site becomes unavailable)")
    def iis_site_stop(self, p: IisSiteP):
        return self._iis("Stop-Website", p.name, "Get-Website -Name $Name | Select-Object Name,State")

    @operation("windows.iis.apppool.recycle", "Recycle IIS app pool", risk="change", params=IisPoolP, changes="Recycle application pool '{name}'")
    def iis_pool_recycle(self, p: IisPoolP):
        return self._iis("Restart-WebAppPool", p.name, "Get-Item ('IIS:\\AppPools\\' + $Name) | Select-Object Name,State")

    # -------------------------------------------------------------- Active Directory
    AD = staticmethod(lambda: need_module("ActiveDirectory", "install RSAT-AD-PowerShell or target a domain controller"))

    @operation("windows.ad.users.list", "List AD users", risk="read", params=AdUserListP)
    def ad_users(self, p: AdUserListP):
        data = self._invoke(ps("[string]$Search,[string]$Base,[int]$Max", self.AD() + """
$f = if ($Search) { "SamAccountName -like '*$($Search -replace "'","''")*' -or Name -like '*$($Search -replace "'","''")*'" } else { '*' }
$a = @{ Filter=$f; Properties=@('DisplayName','mail','Enabled','LastLogonDate','LockedOut','whenCreated'); ResultSetSize=$Max }
if ($Base) { $a.SearchBase = $Base }
Get-ADUser @a | Select-Object SamAccountName,DisplayName,mail,Enabled,LockedOut,LastLogonDate,DistinguishedName"""),
            {"Search": p.search, "Base": p.search_base, "Max": p.max_results})
        return self._ok(data)

    @operation("windows.ad.user.create", "Create AD user", risk="change", params=AdUserCreateP, secret_params=("password",),
               changes="Create AD user '{sam_account_name}' ({user_principal_name}) in {ou}, enabled={enabled}")
    def ad_user_create(self, p: AdUserCreateP):
        data = self._invoke(ps("[string]$Sam,[string]$Given,[string]$Sur,[string]$Display,[string]$Upn,[string]$Ou,[string]$Password,[bool]$Enabled,[bool]$Change", self.AD() + """
$sec = ConvertTo-SecureString $Password -AsPlainText -Force
$n = if ($Display) { $Display } else { $Sam }
New-ADUser -SamAccountName $Sam -Name $n -GivenName $Given -Surname $Sur -DisplayName $Display -UserPrincipalName $Upn -Path $Ou -AccountPassword $sec -Enabled $Enabled -ChangePasswordAtLogon $Change
Get-ADUser -Identity $Sam | Select-Object SamAccountName,Enabled,DistinguishedName"""),
            {"Sam": p.sam_account_name, "Given": p.given_name, "Sur": p.surname, "Display": p.display_name,
             "Upn": p.user_principal_name, "Ou": p.ou, "Password": p.password, "Enabled": p.enabled, "Change": p.change_password_at_logon})
        return self._ok(data, verification="User found in directory", rollback=f"Remove-ADUser -Identity '{p.sam_account_name}'")

    @operation("windows.ad.user.set_enabled", "Enable/disable AD user", risk="change", params=AdUserEnableP, changes="Set AD user '{sam_account_name}' enabled={enabled}")
    def ad_user_enable(self, p: AdUserEnableP):
        data = self._invoke(ps("[string]$Sam,[bool]$On", self.AD() + "if ($On) { Enable-ADAccount -Identity $Sam } else { Disable-ADAccount -Identity $Sam }; Get-ADUser -Identity $Sam | Select-Object SamAccountName,Enabled"),
                            {"Sam": p.sam_account_name, "On": p.enabled})
        ok = data and data[0]["Enabled"] == p.enabled
        return OpResult(status="succeeded" if ok else "failed", data=data, output=json.dumps(data),
                        verification=f"Enabled = {data[0]['Enabled']}", rollback=f"Set enabled={not p.enabled}")

    @operation("windows.ad.user.unlock", "Unlock AD user", risk="change", params=AdUserP, changes="Unlock AD account '{sam_account_name}'")
    def ad_user_unlock(self, p: AdUserP):
        data = self._invoke(ps("[string]$Sam", self.AD() + "Unlock-ADAccount -Identity $Sam; Get-ADUser -Identity $Sam -Properties LockedOut | Select-Object SamAccountName,LockedOut"), {"Sam": p.sam_account_name})
        return self._ok(data, verification=f"LockedOut = {data[0]['LockedOut']}")

    @operation("windows.ad.user.reset_password", "Reset AD password", risk="change", params=AdResetPwP, secret_params=("new_password",),
               changes="Reset password for AD user '{sam_account_name}' (must change at logon: {change_password_at_logon})")
    def ad_user_reset(self, p: AdResetPwP):
        self._invoke(ps("[string]$Sam,[string]$Password,[bool]$Change", self.AD() + """
Set-ADAccountPassword -Identity $Sam -Reset -NewPassword (ConvertTo-SecureString $Password -AsPlainText -Force)
Set-ADUser -Identity $Sam -ChangePasswordAtLogon $Change"""), {"Sam": p.sam_account_name, "Password": p.new_password, "Change": p.change_password_at_logon})
        return OpResult(output=f"Password reset for {p.sam_account_name}", rollback="Not reversible: previous password is not retained")

    @operation("windows.ad.groups.list", "List AD groups", risk="read", params=AdGroupListP)
    def ad_groups(self, p: AdGroupListP):
        data = self._invoke(ps("[string]$Search", self.AD() + """
$f = if ($Search) { "Name -like '*$($Search -replace "'","''")*'" } else { '*' }
Get-ADGroup -Filter $f -Properties Description,member | Select-Object -First 500 Name,@{n='Scope';e={$_.GroupScope.ToString()}},@{n='Category';e={$_.GroupCategory.ToString()}},Description,@{n='MemberCount';e={$_.member.Count}},DistinguishedName"""),
            {"Search": p.search})
        return self._ok(data)

    @operation("windows.ad.group.add_member", "Add member to AD group", risk="change", params=AdGroupMemberP, changes="Add '{member}' to AD group '{group}'")
    def ad_group_add(self, p: AdGroupMemberP):
        self._invoke(ps("[string]$Group,[string]$Member", self.AD() + "Add-ADGroupMember -Identity $Group -Members $Member"), {"Group": p.group, "Member": p.member})
        chk = self._invoke(ps("[string]$Group,[string]$Member", self.AD() + "[pscustomobject]@{ IsMember = [bool](Get-ADGroupMember -Identity $Group | Where-Object SamAccountName -eq $Member) }"), {"Group": p.group, "Member": p.member})
        ok = chk and chk[0]["IsMember"]
        return OpResult(status="succeeded" if ok else "failed", output=f"{p.member} added to {p.group}", verification=f"IsMember = {ok}",
                        rollback=f"Remove-ADGroupMember -Identity '{p.group}' -Members '{p.member}' -Confirm:$false")

    @operation("windows.ad.group.remove_member", "Remove member from AD group", risk="change", params=AdGroupMemberP, changes="Remove '{member}' from AD group '{group}'")
    def ad_group_remove(self, p: AdGroupMemberP):
        self._invoke(ps("[string]$Group,[string]$Member", self.AD() + "Remove-ADGroupMember -Identity $Group -Members $Member -Confirm:$false"), {"Group": p.group, "Member": p.member})
        return OpResult(output=f"{p.member} removed from {p.group}", rollback=f"Add-ADGroupMember -Identity '{p.group}' -Members '{p.member}'")

    @operation("windows.ad.ous.list", "List OUs", risk="read")
    def ad_ous(self, p):
        return self._ok(self._invoke(ps("", self.AD() + "Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion,gPLink | Select-Object Name,DistinguishedName,ProtectedFromAccidentalDeletion,@{n='HasGpoLinks';e={[bool]$_.gPLink}}")))

    @operation("windows.ad.ou.create", "Create OU", risk="change", params=AdOuCreateP, changes="Create OU '{name}' under {parent_dn}")
    def ad_ou_create(self, p: AdOuCreateP):
        data = self._invoke(ps("[string]$Name,[string]$Parent,[bool]$Protect", self.AD() + "New-ADOrganizationalUnit -Name $Name -Path $Parent -ProtectedFromAccidentalDeletion $Protect; Get-ADOrganizationalUnit -Identity (\"OU=$Name,$Parent\") | Select-Object Name,DistinguishedName"),
                            {"Name": p.name, "Parent": p.parent_dn, "Protect": p.protect_from_deletion})
        return self._ok(data, rollback=f"Set-ADOrganizationalUnit -Identity 'OU={p.name},{p.parent_dn}' -ProtectedFromAccidentalDeletion $false; Remove-ADOrganizationalUnit ...")

    # -------------------------------------------------------------- DNS
    DNS = staticmethod(lambda: need_module("DnsServer", "install RSAT-DNS-Server or target the DNS server"))

    @operation("windows.dns.zones.list", "List DNS zones", risk="read")
    def dns_zones(self, p):
        return self._ok(self._invoke(ps("", self.DNS() + "Get-DnsServerZone | Select-Object ZoneName,ZoneType,IsDsIntegrated,IsReverseLookupZone,DynamicUpdate")))

    @operation("windows.dns.records.list", "List DNS records", risk="read", params=DnsZoneP)
    def dns_records(self, p: DnsZoneP):
        return self._ok(self._invoke(ps("[string]$Zone", self.DNS() + """Get-DnsServerResourceRecord -ZoneName $Zone | Select-Object -First 2000 HostName,RecordType,
 @{n='TTL';e={$_.TimeToLive.TotalSeconds}},@{n='Data';e={ switch ($_.RecordType) { 'A' {$_.RecordData.IPv4Address.ToString()} 'AAAA' {$_.RecordData.IPv6Address.ToString()} 'CNAME' {$_.RecordData.HostNameAlias} 'MX' {$_.RecordData.MailExchange} 'NS' {$_.RecordData.NameServer} default {''} } }}"""), {"Zone": p.zone}))

    @operation("windows.dns.record.add", "Add DNS record", risk="change", params=DnsRecordAddP, changes="Add {type} record {name}.{zone} -> {value} (TTL {ttl_seconds}s)")
    def dns_add(self, p: DnsRecordAddP):
        body = self.DNS() + """
$ttl = [TimeSpan]::FromSeconds($Ttl)
if ($Type -eq 'A') { Add-DnsServerResourceRecordA -ZoneName $Zone -Name $Name -IPv4Address $Value -TimeToLive $ttl }
else { Add-DnsServerResourceRecordCName -ZoneName $Zone -Name $Name -HostNameAlias $Value -TimeToLive $ttl }
Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType $Type | Select-Object HostName,RecordType"""
        data = self._invoke(ps("[string]$Zone,[string]$Name,[string]$Type,[string]$Value,[int]$Ttl", body),
                            {"Zone": p.zone, "Name": p.name, "Type": p.type, "Value": p.value, "Ttl": p.ttl_seconds})
        return self._ok(data, verification="Record resolvable on server", rollback=f"Remove-DnsServerResourceRecord -ZoneName {p.zone} -Name {p.name} -RRType {p.type} -Force")

    @operation("windows.dns.record.remove", "Remove DNS record", risk="critical", params=DnsRecordRemoveP, changes="Remove {type} record(s) {name}.{zone}")
    def dns_remove(self, p: DnsRecordRemoveP):
        before = self._invoke(ps("[string]$Zone,[string]$Name,[string]$Type", self.DNS() + "Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType $Type | Select-Object HostName,RecordType,@{n='Data';e={ if ($_.RecordData.IPv4Address) { $_.RecordData.IPv4Address.ToString() } else { $_.RecordData.HostNameAlias } }}"),
                              {"Zone": p.zone, "Name": p.name, "Type": p.type})
        self._invoke(ps("[string]$Zone,[string]$Name,[string]$Type", self.DNS() + "Remove-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType $Type -Force"), {"Zone": p.zone, "Name": p.name, "Type": p.type})
        return OpResult(output=f"Removed {p.type} {p.name}.{p.zone}", before=json.dumps(before), rollback=f"Re-add records: {json.dumps(before)}")

    # -------------------------------------------------------------- DHCP
    DHCP = staticmethod(lambda: need_module("DhcpServer", "install RSAT-DHCP or target the DHCP server"))

    @operation("windows.dhcp.scopes.list", "List DHCP scopes", risk="read")
    def dhcp_scopes(self, p):
        return self._ok(self._invoke(ps("", self.DHCP() + """Get-DhcpServerv4Scope | ForEach-Object { $s = Get-DhcpServerv4ScopeStatistics -ScopeId $_.ScopeId
 [pscustomobject]@{ ScopeId=$_.ScopeId.ToString(); Name=$_.Name; State=$_.State; StartRange=$_.StartRange.ToString(); EndRange=$_.EndRange.ToString(); InUse=$s.InUse; Free=$s.Free; PercentageInUse=$s.PercentageInUse } }""")))

    @operation("windows.dhcp.leases.list", "List DHCP leases", risk="read", params=DhcpScopeP)
    def dhcp_leases(self, p: DhcpScopeP):
        return self._ok(self._invoke(ps("[string]$Scope", self.DHCP() + "Get-DhcpServerv4Lease -ScopeId $Scope | Select-Object @{n='IPAddress';e={$_.IPAddress.ToString()}},ClientId,HostName,AddressState,LeaseExpiryTime"), {"Scope": p.scope_id}))

    @operation("windows.dhcp.reservation.add", "Add DHCP reservation", risk="change", params=DhcpReservationP, changes="Reserve {ip_address} for {client_id} in scope {scope_id}")
    def dhcp_reserve(self, p: DhcpReservationP):
        data = self._invoke(ps("[string]$Scope,[string]$Ip,[string]$Mac,[string]$Name", self.DHCP() + "Add-DhcpServerv4Reservation -ScopeId $Scope -IPAddress $Ip -ClientId $Mac -Name $Name; Get-DhcpServerv4Reservation -IPAddress $Ip | Select-Object @{n='IPAddress';e={$_.IPAddress.ToString()}},ClientId,Name"),
                            {"Scope": p.scope_id, "Ip": p.ip_address, "Mac": p.client_id.replace(":", "-"), "Name": p.name})
        return self._ok(data, rollback=f"Remove-DhcpServerv4Reservation -IPAddress {p.ip_address}")

    # -------------------------------------------------------------- Group Policy
    GP = staticmethod(lambda: need_module("GroupPolicy", "install GPMC / RSAT-Group-Policy-Management or target a DC"))

    @operation("windows.gpo.list", "List GPOs", risk="read")
    def gpo_list(self, p):
        return self._ok(self._invoke(ps("", self.GP() + "Get-GPO -All | Select-Object DisplayName,Id,@{n='GpoStatus';e={$_.GpoStatus.ToString()}},CreationTime,ModificationTime,Description")))

    @operation("windows.gpo.inspect", "Inspect GPO links", risk="read", params=GpoP)
    def gpo_inspect(self, p: GpoP):
        data = self._invoke(ps("[string]$Name", self.GP() + """
$g = Get-GPO -Name $Name
[xml]$x = Get-GPOReport -Name $Name -ReportType Xml
[pscustomobject]@{ DisplayName=$g.DisplayName; Id=$g.Id; Status=$g.GpoStatus.ToString(); Modified=$g.ModificationTime;
 Links=@($x.GPO.LinksTo | ForEach-Object { [pscustomobject]@{ Path=$_.SOMPath; Enabled=$_.Enabled; NoOverride=$_.NoOverride } });
 ComputerVersion=$g.Computer.DSVersion; UserVersion=$g.User.DSVersion }"""), {"Name": p.name})
        return self._ok(data[0] if data else {})

    @operation("windows.gpo.create", "Create GPO", risk="change", params=GpoCreateP, changes="Create (unlinked) Group Policy Object '{name}'")
    def gpo_create(self, p: GpoCreateP):
        data = self._invoke(ps("[string]$Name,[string]$Comment", self.GP() + "if (Get-GPO -Name $Name -ErrorAction SilentlyContinue) { throw \"GPO '$Name' already exists\" }; New-GPO -Name $Name -Comment $Comment | Select-Object DisplayName,Id"),
                            {"Name": p.name, "Comment": p.comment})
        return self._ok(data, verification="GPO created (not linked)", rollback=f"Remove-GPO -Name '{p.name}'")

    @operation("windows.gpo.link", "Link GPO", risk="critical", params=GpoLinkP, changes="Link GPO '{name}' to {target_dn} (enforced={enforced}, enabled={link_enabled})")
    def gpo_link(self, p: GpoLinkP):
        data = self._invoke(ps("[string]$Name,[string]$Target,[bool]$Enforced,[bool]$Enabled", self.GP() + """
$e = if ($Enforced) { 'Yes' } else { 'No' }; $l = if ($Enabled) { 'Yes' } else { 'No' }
New-GPLink -Name $Name -Target $Target -Enforced $e -LinkEnabled $l | Select-Object DisplayName,Target,Enabled,Enforced"""),
            {"Name": p.name, "Target": p.target_dn, "Enforced": p.enforced, "Enabled": p.link_enabled})
        return self._ok(data, rollback=f"Remove-GPLink -Name '{p.name}' -Target '{p.target_dn}'")

    @operation("windows.gpo.set_registry", "Set GPO registry policy", risk="critical", params=GpoRegistryP,
               changes="In GPO '{name}' set {key}\\{value_name} ({value_type}) = {value}")
    def gpo_set_registry(self, p: GpoRegistryP):
        before = self._invoke(ps("[string]$Name,[string]$Key,[string]$ValueName", self.GP() + "try { Get-GPRegistryValue -Name $Name -Key $Key -ValueName $ValueName | Select-Object KeyPath,ValueName,Value,@{n='Type';e={$_.Type.ToString()}} } catch { @() }"),
                              {"Name": p.name, "Key": p.key, "ValueName": p.value_name})
        val = int(p.value) if p.value_type in ("DWord", "QWord") else p.value
        self._invoke(ps("[string]$Name,[string]$Key,[string]$ValueName,[string]$Type,$Value", self.GP() + "Set-GPRegistryValue -Name $Name -Key $Key -ValueName $ValueName -Type $Type -Value $Value | Out-Null"),
                     {"Name": p.name, "Key": p.key, "ValueName": p.value_name, "Type": p.value_type, "Value": val})
        return OpResult(output=f"Set {p.key}\\{p.value_name} in {p.name}", before=json.dumps(before), after=json.dumps({"value": p.value}),
                        rollback=(f"Restore previous value {json.dumps(before)}" if before else f"Remove-GPRegistryValue -Name '{p.name}' -Key '{p.key}' -ValueName '{p.value_name}'"))

    @operation("windows.gpo.report", "Generate GPO report", risk="read", params=GpoReportP)
    def gpo_report(self, p: GpoReportP):
        data = self._invoke(ps("[string]$Name,[string]$Type", self.GP() + "[pscustomobject]@{ Report = (Get-GPOReport -Name $Name -ReportType $Type) }"), {"Name": p.name, "Type": p.report_type})
        report = data[0]["Report"] if data else ""
        return OpResult(output=f"{p.report_type} report generated ({len(report)} chars)", data={"report": report, "type": p.report_type})

    @operation("windows.gpo.collect", "Collect all GPOs for reporting", risk="read", params=GpoCollectP,
               description="Reads every GPO (Get-GPOReport XML), OU links, inheritance and precedence, domain controllers and SYSVOL "
                           "consistency, and stores a snapshot for Group Policy reports. Changes nothing.")
    def gpo_collect(self, p: GpoCollectP):
        data = self._invoke(ps("[string]$Domain", self.GP() + self.AD() + r"""
$d = if ($Domain) { Get-ADDomain -Identity $Domain } else { Get-ADDomain }
$srv = $d.PDCEmulator
$dcs = @(Get-ADDomainController -Filter * -Server $srv | Select-Object HostName,Site,IPv4Address,OperatingSystem,IsGlobalCatalog,IsReadOnly,@{n='Roles';e={$_.OperationMasterRoles -join ','}})
# -All can return the report as several strings; join so one XML document is returned
$xml = (@(Get-GPOReport -All -ReportType Xml -Domain $d.DNSRoot -Server $srv) -join "`n")
$ous = @([pscustomobject]@{ DistinguishedName=$d.DistinguishedName; CanonicalName=$d.DNSRoot }) + @(Get-ADOrganizationalUnit -Filter * -Server $srv -Properties CanonicalName | Select-Object DistinguishedName,CanonicalName)
$warn = @()
$inh = foreach ($o in $ous) {
  try { $i = Get-GPInheritance -Target $o.DistinguishedName -Domain $d.DNSRoot -Server $srv
    [pscustomobject]@{ path=$o.CanonicalName.TrimEnd('/'); dn=$o.DistinguishedName; blocked=[bool]$i.GpoInheritanceBlocked
      links=@($i.GpoLinks | ForEach-Object { [pscustomobject]@{ guid=$_.GpoId.ToString(); order=$_.Order; enforced=[bool]$_.Enforced; enabled=[bool]$_.Enabled } })
      inherited=@($i.InheritedGpoLinks | ForEach-Object { $_.GpoId.ToString() }) } }
  catch { $warn += "Inheritance for $($o.DistinguishedName): $($_.Exception.Message)" } }
$guids = @(Get-GPO -All -Domain $d.DNSRoot -Server $srv | ForEach-Object { $_.Id.ToString() })
$pol = "\\$($d.DNSRoot)\SYSVOL\$($d.DNSRoot)\Policies"
$missing = @(); $orph = @()
if (Test-Path $pol) {
  $missing = @($guids | Where-Object { -not (Test-Path (Join-Path $pol "{$_}")) })
  $orph = @(Get-ChildItem $pol -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\{[0-9A-Fa-f-]{36}\}$' } | ForEach-Object { $_.Name.Trim('{}') } | Where-Object { $guids -notcontains $_ })
} else { $warn += "SYSVOL path $pol not reachable - orphan check skipped" }
[pscustomobject]@{ domain=[pscustomobject]@{ dns_root=$d.DNSRoot; netbios=$d.NetBIOSName; dn=$d.DistinguishedName; mode=$d.DomainMode.ToString();
    forest=$d.Forest; pdc=$d.PDCEmulator; rid_master=$d.RIDMaster; infrastructure_master=$d.InfrastructureMaster }
  dcs=$dcs; xml=$xml; ous=@($inh); sysvol_missing=$missing; sysvol_orphans=$orph; warnings=$warn }"""), {"Domain": p.domain})
        r = data[0] if data else {}
        n = (r.get("xml") or "").count("<GPO ")
        return OpResult(output=f"Collected {n} GPO(s), {len(r.get('ous') or [])} OU(s), {len(r.get('dcs') or [])} domain controller(s) "
                               f"from {(r.get('domain') or {}).get('dns_root', '?')}", data=r)

    @operation("windows.gpo.rsop", "Resultant policy (gpresult)", risk="read", params=GpoRsopP,
               description="Runs Get-GPResultantSetOfPolicy for a computer (and optionally a user) and explains which GPOs applied and why others did not.")
    def gpo_rsop(self, p: GpoRsopP):
        data = self._invoke(ps("[string]$Computer,[string]$User", self.GP() + r"""
$f = Join-Path $env:TEMP ("infrapilot-rsop-" + [guid]::NewGuid().ToString() + ".xml")
$a = @{ ReportType='Xml'; Path=$f }
if ($Computer) { $a.Computer = $Computer }
if ($User) { $a.User = $User }
try { Get-GPResultantSetOfPolicy @a | Out-Null; [pscustomobject]@{ xml = (Get-Content -Raw -Path $f) } } finally { Remove-Item $f -ErrorAction SilentlyContinue }"""),
            {"Computer": p.computer, "User": p.user})
        xml = (data[0] if data else {}).get("xml") or ""
        from app.services.gpo.parser import GpoXmlError, parse_rsop
        try:
            parsed = parse_rsop(xml)
        except GpoXmlError as exc:
            return OpResult(status="failed", output=f"Could not read the RSoP report: {exc}", data={"xml": xml[:200000]})
        lines = []
        for scope in ("computer", "user"):
            r = parsed.get(scope)
            if not r:
                continue
            lines.append(f"{scope.title()}: {r['name']} (OU {r['som']}, site {r['site']})")
            for g in r["gpos"]:
                lines.append(f"  {'APPLIED ' if g['applied'] else 'NOT APPLIED'}  {g['name']}" + ("" if g["applied"] else f"  - {'; '.join(g['reasons'])}"))
            for e in r["extension_errors"]:
                lines.append(f"  ERROR in {e['extension']}: code {e['error_code']}")
        return OpResult(output="\n".join(lines) or "No results", data={**parsed, "xml": xml[:500000]})

    @operation("windows.gpo.backup", "Back up GPO", risk="change", params=GpoBackupP,
               changes="Back up GPO '{name}' to {path}", description="Backup-GPO to a folder on the server; the backup can later be restored with approval.")
    def gpo_backup(self, p: GpoBackupP):
        data = self._invoke(ps("[string]$Name,[string]$Path,[string]$Comment", self.GP() + r"""
if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
$b = Backup-GPO -Name $Name -Path $Path -Comment $Comment
[pscustomobject]@{ BackupId=$b.Id.ToString(); GpoId=$b.GpoId.ToString(); DisplayName=$b.DisplayName; CreationTime=$b.CreationTime; BackupDirectory=$b.BackupDirectory;
  xml=(@(Get-GPOReport -Name $Name -ReportType Xml) -join "`n") }"""), {"Name": p.name, "Path": p.path, "Comment": p.comment or "InfraPilot backup"})
        r = data[0] if data else {}
        return OpResult(output=f"Backed up '{p.name}' to {p.path} (backup id {r.get('BackupId')})", data=r,
                        verification=f"Backup folder {r.get('BackupDirectory')}\\{{{r.get('BackupId')}}} created")

    @operation("windows.gpo.backups.list", "List GPO backups", risk="read", params=GpoBackupListP)
    def gpo_backups_list(self, p: GpoBackupListP):
        data = self._invoke(ps("[string]$Path", r"""
if (-not (Test-Path $Path)) { throw "Folder $Path does not exist" }
Get-ChildItem -Path $Path -Directory | Where-Object { $_.Name -match '^\{[0-9A-Fa-f-]{36}\}$' } | ForEach-Object {
  $i = Join-Path $_.FullName 'bkupInfo.xml'
  if (Test-Path $i) { [xml]$x = Get-Content -Raw $i
    [pscustomobject]@{ BackupId=$_.Name.Trim('{}'); GpoName=$x.BackupInst.GPODisplayName.'#cdata-section'; GpoId=$x.BackupInst.GPOGuid.'#cdata-section'.Trim('{}');
      Domain=$x.BackupInst.GPODomain.'#cdata-section'; Time=$x.BackupInst.BackupTime.'#cdata-section'; Comment=$x.BackupInst.Comment.'#cdata-section' } } } |
  Sort-Object Time -Descending"""), {"Path": p.path})
        return self._ok(data)

    @operation("windows.gpo.restore", "Restore GPO from backup", risk="critical", params=GpoRestoreP, check_mode=True,
               changes="Restore GPO '{name}' from backup {backup_id} in {path} (replaces all current settings of the GPO)",
               description="Dry-run compares the current GPO with the backup without changing anything. The real restore captures the "
                           "GPO before and after and stores both versions for a before/after comparison.")
    def gpo_restore(self, p: GpoRestoreP, check_mode: bool = False):
        bid = p.backup_id.strip("{}")
        data = self._invoke(ps("[string]$Name,[string]$Path,[string]$BackupId,[bool]$DryRun", self.GP() + r"""
$bdir = Join-Path $Path ("{" + $BackupId + "}")
if (-not (Test-Path $bdir)) { throw "Backup $BackupId not found in $Path" }
$before = (@(Get-GPOReport -Name $Name -ReportType Xml) -join "`n")
$backupReport = Get-Content -Raw (Join-Path $bdir 'gpreport.xml')
if ($DryRun) { [pscustomobject]@{ before_xml=$before; after_xml=$backupReport; dry_run=$true } }
else { Restore-GPO -Name $Name -Path $Path -BackupId $BackupId | Out-Null
  [pscustomobject]@{ before_xml=$before; after_xml=(@(Get-GPOReport -Name $Name -ReportType Xml) -join "`n"); dry_run=$false } }"""),
            {"Name": p.name, "Path": p.path, "BackupId": bid, "DryRun": check_mode})
        r = data[0] if data else {}
        from app.services.gpo import analysis as gpa
        from app.services.gpo.parser import GpoXmlError, parse_report
        try:
            d = gpa.diff_versions(parse_report(r.get("before_xml") or "")[0], parse_report(r.get("after_xml") or "")[0])
        except (GpoXmlError, IndexError):
            d = {"settings": [], "metadata": [], "counts": {}}
        lines = [f"{c['change'].upper():9} [{c['scope']}] {c['name']}: {c['before'] or '-'} -> {c['after'] or '-'}" for c in d["settings"]]
        head = "DRY RUN - nothing changed. Restoring would make these changes:" if check_mode else f"Restored '{p.name}' from backup {bid}. Changes:"
        return OpResult(output=head + "\n" + ("\n".join(lines) or "(no setting differences)"),
                        data={**r, "diff": d}, before=r.get("before_xml"), after=None if check_mode else r.get("after_xml"),
                        verification=None if check_mode else "GPO report read back after restore",
                        rollback=None if check_mode else f"Restore the backup taken before this change (Backup-GPO), or re-run with the previous backup id")

    @operation("windows.gpupdate", "Run GPUpdate", risk="change", params=GpUpdateP, changes="Refresh Group Policy on {computer} (force={force})")
    def gpupdate(self, p: GpUpdateP):
        if p.computer:
            self._invoke(ps("[string]$Computer,[bool]$Force", self.GP() + "Invoke-GPUpdate -Computer $Computer -Force:$Force -RandomDelayInMinutes 0"), {"Computer": p.computer, "Force": p.force})
            return OpResult(output=f"GPUpdate scheduled on {p.computer}")
        data = self._invoke(ps("[bool]$Force", "$o = if ($Force) { gpupdate.exe /force /wait:120 2>&1 } else { gpupdate.exe /wait:120 2>&1 }; [pscustomobject]@{ Output = ($o -join \"`n\"); ExitCode=$LASTEXITCODE }"), {"Force": p.force})
        row = data[0]
        return OpResult(status="succeeded" if row.get("ExitCode") == 0 else "failed", output=row.get("Output", ""))
