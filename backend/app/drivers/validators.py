"""Reusable strict field types for operation parameters.

These are deliberately narrow allow-lists: parameters end up in PowerShell parameter
binding, SSH command arguments (additionally shlex-quoted) or vendor CLI config lines.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field, StringConstraints

ServiceName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.@\-]{1,128}$")]
UnitName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.@:\-]{1,200}$")]
PackageName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9+_.:\-]{0,127}$")]
FeatureName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9\-_.]{1,128}$")]
AccountName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")]
# DOMAIN\user or user@domain or plain
Principal = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9 ._\-\\@$]{1,256}$")]
WinPath = Annotated[str, StringConstraints(pattern=r"^[A-Za-z]:\\(?:[^<>:\"/|?*\x00-\x1f]+\\?)*$", max_length=260)]
UnixPath = Annotated[str, StringConstraints(pattern=r"^/(?:[A-Za-z0-9._@+\-]+/?)*$", max_length=1024)]
ShareName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._\-$ ]{1,80}$")]
DnsName = Annotated[str, StringConstraints(max_length=253, pattern=r"^(?:(?:[A-Za-z0-9_](?:[A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?\.?)+|@)$")]
IPv4 = Annotated[str, StringConstraints(pattern=r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")]
Cidr = Annotated[str, StringConstraints(pattern=r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}/(3[0-2]|[12]?\d)$")]
Mac = Annotated[str, StringConstraints(pattern=r"^[0-9A-Fa-f]{2}([-:]?[0-9A-Fa-f]{2}){5}$")]
DistinguishedName = Annotated[str, StringConstraints(pattern=r"^(?:[A-Za-z]+=[^,=\x00-\x1f]+,)*[A-Za-z]+=[^,=\x00-\x1f]+$", max_length=500)]
FreeLabel = Annotated[str, StringConstraints(pattern=r"^[^\x00-\x1f`$;|&<>]{0,200}$")]
InterfaceName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9/.:\- ]{0,63}$")]
VlanId = Annotated[int, Field(ge=1, le=4094)]
VlanList = Annotated[str, StringConstraints(pattern=r"^\d{1,4}(-\d{1,4})?(,\d{1,4}(-\d{1,4})?)*$")]
Port = Annotated[int, Field(ge=1, le=65535)]
Octal = Annotated[str, StringConstraints(pattern=r"^[0-7]{3,4}$")]
GpoName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9 ._\-()]{1,200}$")]
RegistryKey = Annotated[str, StringConstraints(pattern=r"^HK(LM|CU)\\[A-Za-z0-9 _.\\\-]{1,240}$")]
Thumbprint = Annotated[str, StringConstraints(pattern=r"^[A-Fa-f0-9]{40}$")]
TaskPath = Annotated[str, StringConstraints(pattern=r"^\\([A-Za-z0-9 ._\-]+\\)*$")]
TaskName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9 ._\-]{1,200}$")]
ObjectName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9 ._\-]{1,63}$")]
