"""Active Directory LDAP/LDAPS authentication.

Settings live in system_settings['ldap'] (non-secret) and the bind password in the vault.
Flow: bind with service account -> locate user by sAMAccountName/UPN (escaped filter)
-> bind as the user DN with the supplied password -> read memberOf -> map groups to roles.
"""
from __future__ import annotations

import ssl
from dataclasses import dataclass, field

from ldap3 import ALL, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars


@dataclass
class LdapConfig:
    enabled: bool = False
    host: str = ""
    port: int = 636
    use_ssl: bool = True
    start_tls: bool = False
    verify_cert: bool = True
    ca_cert_file: str | None = None
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_filter: str = "(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={username})))"
    group_role_map: dict[str, str] = field(default_factory=dict)  # group DN (lowercase) -> role name
    default_role: str = ""  # role for directory users in no mapped group ("" = deny sign-in)
    timeout: int = 10


@dataclass
class LdapUser:
    dn: str
    username: str
    display_name: str
    email: str | None
    groups: list[str]


class LdapError(RuntimeError):
    pass


def _server(cfg: LdapConfig) -> Server:
    tls = None
    if cfg.use_ssl or cfg.start_tls:
        tls = Tls(
            validate=ssl.CERT_REQUIRED if cfg.verify_cert else ssl.CERT_NONE,
            ca_certs_file=cfg.ca_cert_file or None,
            version=ssl.PROTOCOL_TLS_CLIENT,
        )
    return Server(cfg.host, port=cfg.port, use_ssl=cfg.use_ssl, tls=tls, get_info=ALL, connect_timeout=cfg.timeout)


def _open(cfg: LdapConfig, user: str, password: str) -> Connection:
    conn = Connection(_server(cfg), user=user, password=password, receive_timeout=cfg.timeout, raise_exceptions=False)
    if cfg.start_tls and not cfg.use_ssl:
        conn.open()
        conn.start_tls()
    if not conn.bind():
        raise LdapError("LDAP bind failed")
    return conn


def test_connection(cfg: LdapConfig) -> str:
    conn = _open(cfg, cfg.bind_dn, cfg.bind_password)
    who = conn.extend.standard.who_am_i()
    conn.unbind()
    return f"Bound successfully as {who or cfg.bind_dn}"


def authenticate(cfg: LdapConfig, username: str, password: str) -> LdapUser | None:
    if not cfg.enabled or not password:
        return None
    svc = _open(cfg, cfg.bind_dn, cfg.bind_password)
    try:
        flt = cfg.user_filter.replace("{username}", escape_filter_chars(username))
        svc.search(cfg.base_dn, flt, attributes=["distinguishedName", "displayName", "mail", "memberOf", "sAMAccountName"])
        if len(svc.entries) != 1:
            return None
        e = svc.entries[0]
        dn = e.entry_dn
    finally:
        svc.unbind()
    try:
        uconn = _open(cfg, dn, password)
        uconn.unbind()
    except LdapError:
        return None
    attrs = e.entry_attributes_as_dict
    return LdapUser(
        dn=dn,
        username=(attrs.get("sAMAccountName") or [username])[0],
        display_name=(attrs.get("displayName") or [username])[0],
        email=(attrs.get("mail") or [None])[0],
        groups=[g.lower() for g in attrs.get("memberOf", [])],
    )
