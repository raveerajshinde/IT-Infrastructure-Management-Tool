"""Readable explanations and the built-in security baseline for Group Policy settings.

The baseline is aligned with the CIS Microsoft Windows Server Benchmark (Level 1) and the Microsoft Security
Baseline. It is a starting point, not a certification: administrators can exclude rules that do not apply
to their organisation (Group Policy -> Compliance), and every exclusion is recorded in the audit log.

Status vocabulary (never assume a missing setting is insecure):
    compliant         configured and matches the baseline
    non_compliant     configured and does not match the baseline
    not_configured    no linked, enabled GPO sets it (it may still be set locally or by other means)
    not_applicable    configured but cannot take effect where it is (e.g. password policy outside the domain root,
                      settings in a disabled half of a GPO, an unlinked GPO)
    unknown           configured but the value could not be interpreted
    no_baseline       configured; the baseline has no expectation for it (informational)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from app.services.gpo.parser import Setting

RISKS = ["critical", "high", "medium", "low", "informational"]
STATUSES = ["compliant", "non_compliant", "not_configured", "not_applicable", "unknown", "no_baseline"]
STATUS_LABEL = {"compliant": "Compliant", "non_compliant": "Non-compliant", "not_configured": "Not configured",
                "not_applicable": "Not applicable", "unknown": "Unknown", "no_baseline": "Configured (no baseline)"}
CATEGORIES = ["Password Policy", "Account Lockout", "Kerberos Policy", "Windows Defender", "Firewall", "Windows Update", "BitLocker",
              "USB Restrictions", "RDP", "PowerShell", "Microsoft Edge", "Google Chrome", "User Rights", "Audit Policy",
              "Security Options", "Windows Services", "Event Log", "Administrative Templates", "Preferences & Other"]
REPORT_GROUPS = {
    "Password and Account Security Policies": ["Password Policy", "Account Lockout", "Kerberos Policy"],
    "Windows Security Policies": ["Windows Defender", "Firewall", "Windows Update", "BitLocker", "USB Restrictions", "RDP", "PowerShell",
                                  "User Rights", "Audit Policy", "Security Options", "Windows Services", "Event Log"],
    "Browser Security Policies": ["Microsoft Edge", "Google Chrome"],
    "Other Configuration": ["Administrative Templates", "Preferences & Other"],
}


@dataclass(frozen=True)
class Rule:
    id: str
    match: tuple[str, ...]        # setting keys (lower-case) or "pname:<policy name>" / "pname:<name>@<path fragment>"
    title: str
    category: str
    expected: str
    check: Callable[[Any], bool | None]
    risk: str
    why: str
    fix: str
    ref: str = "CIS Windows Server Benchmark L1 / Microsoft Security Baseline"
    applies: str = ""             # "domain_account": only effective when linked at the domain root
    scope: str = "computer"


# ------------------------------------------------------------------ value helpers
def _n(v) -> float | None:
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and re.fullmatch(r"-?\d+(\.\d+)?", v.strip()):
        return float(v)
    return None


def between(lo=None, hi=None, not_zero=False):
    def f(v):
        x = _n(v)
        if x is None:
            return None
        if not_zero and x == 0:
            return False
        return (lo is None or x >= lo) and (hi is None or x <= hi)
    return f


def equals(*allowed):
    def f(v):
        if v is None:
            return None
        if isinstance(v, bool):
            return v in allowed
        x = _n(v)
        if x is not None:
            return any(_n(a) == x for a in allowed if not isinstance(a, bool) and _n(a) is not None)
        return str(v).strip().lower() in {str(a).lower() for a in allowed}
    return f


def is_true(v):
    return None if v is None else bool(v) is True


def is_false(v):
    return None if v is None else bool(v) is False


def state(*ok: str, part: tuple[str, Callable[[Any], bool]] | None = None):
    """Administrative Template policy: State in ok (and optional sub-value check)."""
    def f(v):
        if not isinstance(v, dict):
            return None
        st = str(v.get("state", "")).lower()
        if st not in {o.lower() for o in ok}:
            return False
        if part and st == "enabled":
            name, chk = part
            val = next((x for k, x in v.items() if k.lower().startswith(name.lower())), None)
            if val is None:
                return None
            return chk(val)
        return True
    return f


def not_state(bad: str):
    def f(v):
        if not isinstance(v, dict):
            return None
        return str(v.get("state", "")).lower() != bad.lower()
    return f


def contains(text: str):
    return lambda x: text.lower() in str(x).lower()


def audit_includes(success=False, failure=False):
    def f(v):
        if isinstance(v, dict):
            return (not success or v.get("success")) and (not failure or v.get("failure"))
        x = _n(v)
        if x is None:
            return None
        x = int(x)
        return (not success or x in (1, 3)) and (not failure or x in (2, 3))
    return f


_ADMIN_EQ = {"administrators", "domain admins", "enterprise admins"}


def _short(m: str) -> str:
    return m.rsplit("\\", 1)[-1].strip().lower()


def only_members(*allowed: str):
    allow = {a.lower() for a in allowed} | _ADMIN_EQ
    def f(v):
        if not isinstance(v, list):
            return None
        return all(_short(m) in allow or m.upper().startswith("*S-1-5-32-544") for m in v)
    return f


def must_not_include(*bad: str):
    badset = {b.lower() for b in bad}
    def f(v):
        if not isinstance(v, list):
            return None
        return not any(_short(m) in badset for m in v)
    return f


def must_include(*need: str):
    def f(v):
        if not isinstance(v, list):
            return None
        names = {_short(m) for m in v}
        return all(n.lower() in names for n in need)
    return f


def is_empty(v):
    return None if not isinstance(v, list) else len(v) == 0


def url_https(v):
    if not isinstance(v, dict):
        return None
    if str(v.get("state", "")).lower() != "enabled":
        return True
    urls = [str(x) for k, x in v.items() if k != "state" and "http" in str(x).lower()]
    return all(u.lower().startswith("https://") for u in urls) if urls else None


L = "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\"
SP = "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"
NL = "MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\"


def reg(path: str) -> str:
    return "reg:" + path.lower()


# ------------------------------------------------------------------ baseline rules
RULES: list[Rule] = [
    # Password policy
    Rule("PWD-LEN", ("account:minimumpasswordlength",), "Minimum password length", "Password Policy", "14 or more characters",
         between(14), "high", "Short passwords can be guessed or cracked quickly.",
         "Set 'Minimum password length' to 14 or more in the GPO linked at the domain root (or use fine-grained password policies).",
         applies="domain_account"),
    Rule("PWD-CPLX", ("account:passwordcomplexity",), "Password must meet complexity requirements", "Password Policy", "Enabled",
         is_true, "high", "Without complexity users can choose dictionary words, which are cracked in seconds.",
         "Enable 'Password must meet complexity requirements'.", applies="domain_account"),
    Rule("PWD-HIST", ("account:passwordhistorysize",), "Enforce password history", "Password Policy", "24 or more passwords remembered",
         between(24), "medium", "Users can cycle back to a previously compromised password.",
         "Set 'Enforce password history' to 24.", applies="domain_account"),
    Rule("PWD-MAXAGE", ("account:maximumpasswordage",), "Maximum password age", "Password Policy", "1 to 365 days (not 0 = never expires)",
         between(1, 365, not_zero=True), "medium", "Passwords that never expire stay valid indefinitely after a leak.",
         "Set 'Maximum password age' to 365 days or fewer (but not 0).", applies="domain_account"),
    Rule("PWD-MINAGE", ("account:minimumpasswordage",), "Minimum password age", "Password Policy", "1 day or more",
         between(1), "low", "With 0 days users can change their password repeatedly to defeat password history.",
         "Set 'Minimum password age' to 1 day.", applies="domain_account"),
    Rule("PWD-REVERSIBLE", ("account:cleartextpassword",), "Store passwords using reversible encryption", "Password Policy", "Disabled",
         is_false, "critical", "Reversible encryption is equivalent to storing passwords in clear text in Active Directory.",
         "Disable 'Store passwords using reversible encryption' and reset passwords of affected accounts.", applies="domain_account"),
    # Account lockout
    Rule("LOCK-THRESH", ("account:lockoutbadcount",), "Account lockout threshold", "Account Lockout", "1 to 5 invalid attempts (not 0)",
         between(1, 5, not_zero=True), "high", "With no lockout (0) attackers can try unlimited passwords against every account.",
         "Set 'Account lockout threshold' to 5 or fewer invalid logon attempts.", applies="domain_account"),
    Rule("LOCK-DUR", ("account:lockoutduration",), "Account lockout duration", "Account Lockout", "15 minutes or more",
         between(15), "medium", "A short lockout lets password guessing continue almost unhindered.",
         "Set 'Account lockout duration' to 15 minutes or more.", applies="domain_account"),
    Rule("LOCK-RESET", ("account:resetlockoutcount",), "Reset account lockout counter after", "Account Lockout", "15 minutes or more",
         between(15), "medium", "A short reset window allows slow, continuous guessing.",
         "Set 'Reset account lockout counter after' to 15 minutes or more.", applies="domain_account"),
    # Kerberos
    Rule("KRB-TGT", ("account:maxticketage",), "Maximum lifetime for user ticket", "Kerberos Policy", "10 hours or less",
         between(1, 10), "low", "Long-lived tickets extend the usefulness of a stolen ticket.", "Set to 10 hours.", applies="domain_account"),
    Rule("KRB-SKEW", ("account:maxclockskew",), "Maximum tolerance for computer clock synchronization", "Kerberos Policy", "5 minutes or less",
         between(0, 5), "low", "A large tolerance makes replay attacks easier.", "Set to 5 minutes.", applies="domain_account"),
    # Security options
    Rule("SO-GUEST", ("secopt:enableguestaccount",), "Accounts: Guest account status", "Security Options", "Disabled",
         equals(0), "high", "The Guest account allows unauthenticated access.", "Set 'Accounts: Guest account status' to Disabled."),
    Rule("SO-ANONSID", ("secopt:lsaanonymousnamelookup",), "Network access: Allow anonymous SID/Name translation", "Security Options", "Disabled",
         equals(0), "medium", "Anonymous users can enumerate account names, including the renamed Administrator.", "Set to Disabled."),
    Rule("SO-LMCOMPAT", (reg(L + "LmCompatibilityLevel"),), "Network security: LAN Manager authentication level", "Security Options",
         "Send NTLMv2 response only. Refuse LM & NTLM (5)", equals(5), "high",
         "LM and NTLMv1 responses can be cracked or relayed easily.", "Set to 'Send NTLMv2 response only. Refuse LM & NTLM' after confirming no legacy clients need NTLMv1."),
    Rule("SO-NOLMHASH", (reg(L + "NoLMHash"),), "Network security: Do not store LAN Manager hash value on next password change", "Security Options",
         "Enabled", equals(1), "high", "LM hashes are trivially cracked if the directory database is stolen.", "Enable the policy."),
    Rule("SO-RESTRICTSAM", (reg(L + "RestrictAnonymousSAM"),), "Network access: Do not allow anonymous enumeration of SAM accounts", "Security Options",
         "Enabled", equals(1), "medium", "Anonymous users could list local accounts.", "Enable the policy."),
    Rule("SO-RESTRICTANON", (reg(L + "RestrictAnonymous"),), "Network access: Do not allow anonymous enumeration of SAM accounts and shares", "Security Options",
         "Enabled", equals(1), "medium", "Anonymous users could list accounts and shares.", "Enable the policy."),
    Rule("SO-EVERYONEANON", (reg(L + "EveryoneIncludesAnonymous"),), "Network access: Let Everyone permissions apply to anonymous users", "Security Options",
         "Disabled", equals(0), "high", "Anonymous users would receive everything granted to Everyone.", "Disable the policy."),
    Rule("SO-BLANKPW", (reg(L + "LimitBlankPasswordUse"),), "Accounts: Limit local account use of blank passwords to console logon only", "Security Options",
         "Enabled", equals(1), "high", "Accounts with blank passwords could be used over the network.", "Enable the policy."),
    Rule("SO-AUDITSUB", (reg(L + "SCENoApplyLegacyAuditPolicy"),), "Audit: Force audit policy subcategory settings to override category settings",
         "Security Options", "Enabled", equals(1), "medium",
         "Without it, legacy category audit settings can silently override the advanced audit policy.", "Enable the policy."),
    Rule("SO-NTLMCLI", (reg(L + "MSV1_0\\NTLMMinClientSec"),), "Network security: Minimum session security for NTLM SSP based clients",
         "Security Options", "Require NTLMv2 session security, Require 128-bit encryption (537395200)", equals(537395200), "medium",
         "Weak NTLM session security exposes traffic to downgrade attacks.", "Require NTLMv2 session security and 128-bit encryption."),
    Rule("SO-NTLMSRV", (reg(L + "MSV1_0\\NTLMMinServerSec"),), "Network security: Minimum session security for NTLM SSP based servers",
         "Security Options", "Require NTLMv2 session security, Require 128-bit encryption (537395200)", equals(537395200), "medium",
         "Weak NTLM session security exposes traffic to downgrade attacks.", "Require NTLMv2 session security and 128-bit encryption."),
    Rule("SO-SMBSRVSIGN", (reg("MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature"),),
         "Microsoft network server: Digitally sign communications (always)", "Security Options", "Enabled", equals(1), "high",
         "Unsigned SMB allows NTLM relay and man-in-the-middle attacks.", "Enable SMB signing on servers."),
    Rule("SO-SMBCLISIGN", (reg("MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature"),),
         "Microsoft network client: Digitally sign communications (always)", "Security Options", "Enabled", equals(1), "medium",
         "Unsigned SMB allows NTLM relay and man-in-the-middle attacks.", "Enable SMB signing on clients."),
    Rule("SO-PLAINTEXT", (reg("MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnablePlainTextPassword"),),
         "Microsoft network client: Send unencrypted password to third-party SMB servers", "Security Options", "Disabled", equals(0), "high",
         "Passwords would be sent in clear text to some SMB servers.", "Disable the policy."),
    Rule("SO-SIGNSEAL", (reg(NL + "RequireSignOrSeal"),), "Domain member: Digitally encrypt or sign secure channel data (always)",
         "Security Options", "Enabled", equals(1), "high", "Unprotected secure-channel traffic can be tampered with.", "Enable the policy."),
    Rule("SO-STRONGKEY", (reg(NL + "RequireStrongKey"),), "Domain member: Require strong (Windows 2000 or later) session key",
         "Security Options", "Enabled", equals(1), "medium", "Weak session keys can be brute-forced.", "Enable the policy."),
    Rule("SO-LDAPCLI", (reg("MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity"),), "Network security: LDAP client signing requirements",
         "Security Options", "Negotiate signing (1) or higher", between(1), "medium", "Unsigned LDAP traffic can be relayed or modified.",
         "Set to 'Negotiate signing' or 'Require signing'."),
    Rule("SO-LDAPSRV", (reg("MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity"),), "Domain controller: LDAP server signing requirements",
         "Security Options", "Require signing (2)", equals(2), "high", "Domain controllers accepting unsigned binds are open to LDAP relay.",
         "Set to 'Require signing' in the Default Domain Controllers Policy after checking LDAP client compatibility."),
    Rule("SO-UAC", (reg(SP + "EnableLUA"),), "User Account Control: Run all administrators in Admin Approval Mode", "Security Options", "Enabled",
         equals(1), "high", "Disabling UAC runs every administrator process with full rights.", "Enable the policy."),
    Rule("SO-UACADMIN", (reg(SP + "ConsentPromptBehaviorAdmin"),), "User Account Control: Behavior of the elevation prompt for administrators",
         "Security Options", "Prompt for consent/credentials on the secure desktop (1 or 2)", equals(1, 2), "medium",
         "Silent elevation lets malware gain administrator rights without a prompt.", "Set to 'Prompt for consent on the secure desktop'."),
    Rule("SO-UACUSER", (reg(SP + "ConsentPromptBehaviorUser"),), "User Account Control: Behavior of the elevation prompt for standard users",
         "Security Options", "Automatically deny elevation requests (0)", equals(0), "low",
         "Standard users entering admin credentials on prompts encourages credential exposure.", "Set to 'Automatically deny elevation requests'."),
    Rule("SO-IDLE", (reg(SP + "InactivityTimeoutSecs"),), "Interactive logon: Machine inactivity limit", "Security Options", "1 to 900 seconds",
         between(1, 900), "low", "Unattended unlocked sessions can be misused.", "Set to 900 seconds or less."),
    Rule("SO-LASTUSER", (reg(SP + "DontDisplayLastUserName"),), "Interactive logon: Don't display last signed-in", "Security Options", "Enabled",
         equals(1), "low", "Showing the last user name gives attackers half of the credential.", "Enable the policy."),
    Rule("SO-CACHED", (reg("MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount"),),
         "Interactive logon: Number of previous logons to cache", "Security Options", "4 or fewer", between(0, 4), "low",
         "Cached credentials can be extracted and cracked offline.", "Set to 4 or fewer (0-1 on servers that never go offline)."),
    # Audit (legacy categories)
    Rule("AUD-LOGON", ("audit:auditlogonevents",), "Audit logon events", "Audit Policy", "Success and Failure", audit_includes(True, True), "medium",
         "Without logon auditing, brute-force and lateral movement go unnoticed.", "Audit success and failure (prefer the Advanced Audit Policy)."),
    Rule("AUD-ACCLOGON", ("audit:auditaccountlogon",), "Audit account logon events", "Audit Policy", "Success and Failure", audit_includes(True, True),
         "medium", "Domain authentication attempts would not be recorded.", "Audit success and failure."),
    Rule("AUD-ACCMGMT", ("audit:auditaccountmanage",), "Audit account management", "Audit Policy", "Success and Failure", audit_includes(True, True),
         "medium", "Account creation, group changes and resets would not be recorded.", "Audit success and failure."),
    Rule("AUD-POLICY", ("audit:auditpolicychange",), "Audit policy change", "Audit Policy", "Success", audit_includes(True), "medium",
         "An attacker could disable auditing without leaving a trace.", "Audit at least success."),
    Rule("AUD-PRIV", ("audit:auditprivilegeuse",), "Audit privilege use", "Audit Policy", "Failure", audit_includes(failure=True), "low",
         "Failed attempts to use sensitive privileges would not be recorded.", "Audit at least failure."),
    Rule("AUD-SYS", ("audit:auditsystemevents",), "Audit system events", "Audit Policy", "Success and Failure", audit_includes(True, True), "low",
         "Security-relevant system events (e.g. log cleared) would not be recorded.", "Audit success and failure."),
    Rule("AAUD-CRED", ("advaudit:audit credential validation",), "Audit Credential Validation", "Audit Policy", "Success and Failure",
         audit_includes(True, True), "medium", "Credential validation events reveal password-guessing.", "Set to Success and Failure."),
    Rule("AAUD-LOGON", ("advaudit:audit logon",), "Audit Logon", "Audit Policy", "Success and Failure", audit_includes(True, True), "medium",
         "Logon events are the primary record of who accessed what.", "Set to Success and Failure."),
    Rule("AAUD-LOCKOUT", ("advaudit:audit account lockout",), "Audit Account Lockout", "Audit Policy", "Failure", audit_includes(failure=True), "low",
         "Lockouts indicate password attacks.", "Set to include Failure."),
    Rule("AAUD-USERMGMT", ("advaudit:audit user account management",), "Audit User Account Management", "Audit Policy", "Success and Failure",
         audit_includes(True, True), "medium", "Account changes would not be recorded.", "Set to Success and Failure."),
    Rule("AAUD-GROUPMGMT", ("advaudit:audit security group management",), "Audit Security Group Management", "Audit Policy", "Success",
         audit_includes(True), "medium", "Additions to privileged groups would not be recorded.", "Set to include Success."),
    Rule("AAUD-POLCHG", ("advaudit:audit audit policy change",), "Audit Audit Policy Change", "Audit Policy", "Success", audit_includes(True),
         "medium", "Tampering with auditing would not be recorded.", "Set to include Success."),
    Rule("AAUD-SENSPRIV", ("advaudit:audit sensitive privilege use",), "Audit Sensitive Privilege Use", "Audit Policy", "Success and Failure",
         audit_includes(True, True), "low", "Use of powerful privileges would not be recorded.", "Set to Success and Failure."),
    Rule("AAUD-PROC", ("advaudit:audit process creation",), "Audit Process Creation", "Audit Policy", "Success", audit_includes(True), "low",
         "Process creation events are essential for incident investigation.", "Set to include Success."),
    Rule("AAUD-SPECIAL", ("advaudit:audit special logon",), "Audit Special Logon", "Audit Policy", "Success", audit_includes(True), "low",
         "Logons with administrative privileges would not be flagged.", "Set to include Success."),
    # User rights
    Rule("UR-DEBUG", ("right:sedebugprivilege",), "Debug programs", "User Rights", "Administrators only", only_members(), "high",
         "Debug rights allow reading LSASS memory and stealing credentials.", "Grant only to Administrators."),
    Rule("UR-TCB", ("right:setcbprivilege",), "Act as part of the operating system", "User Rights", "No one", is_empty, "critical",
         "Grants complete control of the system.", "Remove all accounts."),
    Rule("UR-TOKEN", ("right:secreatetokenprivilege",), "Create a token object", "User Rights", "No one", is_empty, "critical",
         "Allows creating tokens with any rights.", "Remove all accounts."),
    Rule("UR-OWNER", ("right:setakeownershipprivilege",), "Take ownership of files or other objects", "User Rights", "Administrators only",
         only_members(), "high", "Allows bypassing any file or registry permission.", "Grant only to Administrators."),
    Rule("UR-DRIVER", ("right:seloaddriverprivilege",), "Load and unload device drivers", "User Rights", "Administrators (and Print Operators on DCs)",
         only_members("print operators"), "high", "Drivers run in the kernel; this right gives full control.", "Grant only to Administrators."),
    Rule("UR-BACKUP", ("right:sebackupprivilege",), "Back up files and directories", "User Rights", "Administrators, Backup/Server Operators",
         only_members("backup operators", "server operators"), "medium", "Allows reading any file, including the AD database.", "Restrict to administrators and backup operators."),
    Rule("UR-RESTORE", ("right:serestoreprivilege",), "Restore files and directories", "User Rights", "Administrators, Backup/Server Operators",
         only_members("backup operators", "server operators"), "medium", "Allows overwriting any file, including system binaries.", "Restrict to administrators and backup operators."),
    Rule("UR-RDP", ("right:seremoteinteractivelogonright",), "Allow log on through Remote Desktop Services", "RDP",
         "Administrators and Remote Desktop Users only", only_members("remote desktop users"), "medium",
         "Broad RDP access increases the attack surface for credential theft and lateral movement.",
         "Grant only to Administrators and Remote Desktop Users; manage membership of that group."),
    Rule("UR-NET", ("right:senetworklogonright",), "Access this computer from the network", "User Rights", "Not Everyone, Guests or Anonymous",
         must_not_include("everyone", "guests", "anonymous logon"), "medium", "Guests and anonymous users could connect.", "Remove Everyone/Guests/ANONYMOUS LOGON."),
    Rule("UR-DENYNET", ("right:sedenynetworklogonright",), "Deny access to this computer from the network", "User Rights", "Includes Guests",
         must_include("guests"), "low", "Guests should never log on over the network.", "Add Guests (and Local account on member servers)."),
    Rule("UR-LOCAL", ("right:seinteractivelogonright",), "Allow log on locally", "User Rights", "Not Everyone, Users, Domain Users or Guests",
         must_not_include("everyone", "users", "domain users", "guests", "authenticated users"), "medium",
         "Any user could log on at the console of servers in scope.", "Restrict to administrators (and operators where required)."),
    Rule("UR-DELEG", ("right:seenabledelegationprivilege",), "Enable accounts to be trusted for delegation", "User Rights", "Administrators only",
         only_members(), "high", "Delegation can be abused to impersonate any user.", "Grant only to Administrators on domain controllers; no one elsewhere."),
    Rule("UR-AUDITLOG", ("right:sesecurityprivilege",), "Manage auditing and security log", "User Rights", "Administrators only",
         only_members("exchange servers"), "medium", "Holders can clear the security log and hide activity.", "Grant only to Administrators."),
    # Services / event log
    Rule("SVC-REMREG", ("service:remoteregistry",), "Remote Registry service", "Windows Services", "Disabled or Manual",
         equals("Disabled", "Manual"), "medium", "Remote Registry exposes the registry to remote reads and changes.",
         "Set the service to Disabled unless a monitoring tool needs it."),
    Rule("EVT-SEC", ("eventlog:security:maximumlogsize",), "Security log maximum size", "Event Log", "196,608 KB or more",
         between(196608), "low", "A small security log overwrites evidence quickly.", "Set to at least 196,608 KB and forward logs to a SIEM."),
    # Firewall (Windows Defender Firewall with Advanced Security)
    *[Rule(f"FW-{p.upper()}-ON", (f"fw:{p}:enablefirewall",), f"{p.title()} profile: firewall state", "Firewall", "On",
           lambda v: None if v is None else v in (True, 1, "1", "true", "On"), "high",
           f"With the {p} profile off, every listening service is reachable from the network.", f"Turn the {p} profile On.")
       for p in ("domain", "private", "public")],
    *[Rule(f"FW-{p.upper()}-IN", (f"fw:{p}:defaultinboundaction",), f"{p.title()} profile: inbound connections", "Firewall", "Block (default)",
           lambda v: None if v is None else str(v).lower() in ("true", "1", "block"), "medium",
           "Allowing inbound by default exposes services that have no explicit rule.", "Set inbound connections to Block.")
       for p in ("domain", "private", "public")],
    # Administrative Templates
    Rule("AT-DEFENDER-OFF", ("pname:turn off microsoft defender antivirus", "pname:turn off windows defender antivirus", "pname:turn off windows defender"),
         "Turn off Microsoft Defender Antivirus", "Windows Defender", "Not Enabled", not_state("Enabled"), "critical",
         "Enabling this policy switches off antivirus protection on every computer in scope.",
         "Set to Disabled or Not Configured unless another antivirus product is deployed and monitored."),
    Rule("AT-DEFENDER-RTP", ("pname:turn off real-time protection",), "Turn off real-time protection", "Windows Defender", "Not Enabled",
         not_state("Enabled"), "high", "Files are not scanned when opened or downloaded.", "Set to Disabled or Not Configured."),
    Rule("AT-DEFENDER-BM", ("pname:turn on behavior monitoring",), "Turn on behavior monitoring", "Windows Defender", "Not Disabled",
         not_state("Disabled"), "medium", "Behaviour monitoring detects malware that evades signatures.", "Set to Enabled or Not Configured."),
    Rule("AT-DEFENDER-PUA", ("pname:configure detection for potentially unwanted applications",), "Detection for potentially unwanted applications",
         "Windows Defender", "Enabled: Block", state("Enabled", part=("Configure", contains("block"))), "low",
         "Adware and bundled tools are a common malware entry point.", "Enable and set to Block."),
    Rule("AT-WU-AUTO", ("pname:configure automatic updates",), "Configure Automatic Updates", "Windows Update", "Enabled",
         state("Enabled"), "high", "Disabled automatic updates leave known vulnerabilities unpatched.",
         "Enable and choose an install schedule (or manage updates with WSUS/Intune and document it)."),
    Rule("AT-WU-ACCESS", ("pname:remove access to use all windows update features",), "Remove access to all Windows Update features",
         "Windows Update", "Not Enabled", not_state("Enabled"), "medium", "Blocks updating from Windows Update entirely.", "Set to Disabled or Not Configured."),
    Rule("AT-WU-WSUS", ("pname:specify intranet microsoft update service location",), "Intranet update service (WSUS) location",
         "Windows Update", "HTTPS URL", url_https, "medium", "WSUS over HTTP can be intercepted to push malicious updates.",
         "Publish WSUS over HTTPS and update the URLs."),
    Rule("AT-RDP-NLA", ("pname:require user authentication for remote connections by using network level authentication",),
         "Require Network Level Authentication for RDP", "RDP", "Enabled", state("Enabled"), "high",
         "Without NLA the logon screen is exposed to unauthenticated users and pre-auth exploits.", "Enable the policy."),
    Rule("AT-RDP-ENC", ("pname:set client connection encryption level",), "RDP client connection encryption level", "RDP", "Enabled: High Level",
         state("Enabled", part=("Encryption Level", contains("high"))), "medium", "Low encryption exposes session contents.", "Enable and set to High Level."),
    Rule("AT-RDP-PROMPT", ("pname:always prompt for password upon connection",), "Always prompt for password upon RDP connection", "RDP", "Enabled",
         state("Enabled"), "medium", "Saved credentials in RDP files can be reused by anyone with the file.", "Enable the policy."),
    Rule("AT-RDP-SAVE", ("pname:do not allow passwords to be saved",), "Do not allow RDP passwords to be saved", "RDP", "Enabled",
         state("Enabled"), "medium", "Saved RDP passwords can be extracted from the client.", "Enable the policy."),
    Rule("AT-RDP-LAYER", ("pname:require use of specific security layer for remote (rdp) connections",), "RDP security layer", "RDP", "Enabled: SSL",
         state("Enabled", part=("Security Layer", contains("ssl"))), "medium", "The native RDP layer does not authenticate the server.", "Enable and set to SSL."),
    Rule("AT-PS-SBL", ("pname:turn on powershell script block logging",), "PowerShell Script Block Logging", "PowerShell", "Enabled",
         state("Enabled"), "medium", "Malicious PowerShell is the most common post-exploitation tool; without logging it leaves no trace.", "Enable the policy."),
    Rule("AT-PS-MOD", ("pname:turn on module logging",), "PowerShell Module Logging", "PowerShell", "Enabled", state("Enabled"), "low",
         "Module logging records pipeline execution details.", "Enable for all modules (*)."),
    Rule("AT-PS-EXEC", ("pname:turn on script execution",), "PowerShell script execution policy", "PowerShell", "Not 'Allow all scripts'",
         lambda v: None if not isinstance(v, dict) else not (str(v.get("state", "")).lower() == "enabled"
                                                             and any("allow all" in str(x).lower() for x in v.values())), "medium",
         "Allowing all scripts removes a basic barrier against downloaded scripts.", "Use 'Allow only signed scripts' or 'Allow local scripts and remote signed scripts'."),
    Rule("AT-WINRM-BASIC", ("pname:allow basic authentication",), "WinRM: Allow Basic authentication", "Security Options", "Disabled",
         state("Disabled"), "high", "Basic authentication sends credentials in an easily decoded form.", "Disable the policy (client and service)."),
    Rule("AT-WINRM-UNENC", ("pname:allow unencrypted traffic",), "WinRM: Allow unencrypted traffic", "Security Options", "Disabled",
         state("Disabled"), "high", "Unencrypted WinRM exposes credentials and commands.", "Disable the policy (client and service)."),
    Rule("AT-SMB1", ("pname:configure smb v1 server",), "SMBv1 server", "Security Options", "Disabled", state("Disabled"), "high",
         "SMBv1 is obsolete and was exploited by WannaCry/NotPetya.", "Disable SMBv1 (MS Security Guide ADMX)."),
    Rule("AT-WDIGEST", ("pname:wdigest authentication (disabling may require kb2871997)", "pname:wdigest authentication"),
         "WDigest authentication", "Security Options", "Disabled", state("Disabled"), "high",
         "WDigest keeps clear-text passwords in memory.", "Disable WDigest (MS Security Guide ADMX)."),
    Rule("AT-LLMNR", ("pname:turn off multicast name resolution",), "Turn off multicast name resolution (LLMNR)", "Security Options", "Enabled",
         state("Enabled"), "medium", "LLMNR responses can be spoofed to capture NTLM hashes.", "Enable the policy."),
    Rule("AT-AUTORUN", ("pname:set the default behavior for autorun",), "Default behaviour for AutoRun", "USB Restrictions",
         "Enabled: Do not execute any autorun commands", state("Enabled", part=("Default AutoRun", contains("do not execute"))), "medium",
         "AutoRun can launch malware from removable media.", "Enable and choose 'Do not execute any autorun commands'."),
    Rule("AT-AUTOPLAY", ("pname:turn off autoplay",), "Turn off AutoPlay", "USB Restrictions", "Enabled: All drives",
         state("Enabled", part=("Turn off Autoplay on", contains("all"))), "medium", "AutoPlay can run content from inserted media.", "Enable for All drives."),
    Rule("AT-BL-STARTUP", ("pname:require additional authentication at startup",), "BitLocker: additional authentication at startup",
         "BitLocker", "Enabled", state("Enabled"), "medium", "TPM-only protection is weaker against physical attacks on laptops.",
         "Enable and require a startup PIN where devices leave secure premises."),
    Rule("AT-EDGE-SS", ("pname:configure microsoft defender smartscreen@edge",), "Edge: Microsoft Defender SmartScreen", "Microsoft Edge", "Enabled",
         state("Enabled"), "medium", "SmartScreen blocks known phishing and malware sites.", "Enable the policy."),
    Rule("AT-EDGE-SSBYPASS", ("pname:prevent bypassing microsoft defender smartscreen prompts for sites@edge",), "Edge: prevent bypassing SmartScreen",
         "Microsoft Edge", "Enabled", state("Enabled"), "low", "Users can click through phishing warnings.", "Enable the policy."),
    Rule("AT-EDGE-PWD", ("pname:enable saving passwords to the password manager@edge",), "Edge: save passwords in the browser", "Microsoft Edge",
         "Disabled (use the corporate password manager)", state("Disabled"), "low",
         "Browser-stored passwords are a frequent target of info-stealer malware.", "Disable and provide a managed password manager."),
    Rule("AT-CHROME-SB", ("pname:safe browsing protection level@chrome",), "Chrome: Safe Browsing protection level", "Google Chrome",
         "Enabled: Standard or Enhanced protection", state("Enabled", part=("Safe Browsing", lambda x: "no protection" not in str(x).lower())),
         "medium", "Without Safe Browsing Chrome does not warn about dangerous sites and downloads.", "Enable Standard or Enhanced protection."),
    Rule("AT-CHROME-PWD", ("pname:enable saving passwords to the password manager@chrome",), "Chrome: save passwords in the browser", "Google Chrome",
         "Disabled (use the corporate password manager)", state("Disabled"), "low",
         "Browser-stored passwords are a frequent target of info-stealer malware.", "Disable and provide a managed password manager."),
    Rule("AT-CHROME-DL", ("pname:allow download restrictions@chrome",), "Chrome: download restrictions", "Google Chrome", "Block dangerous downloads",
         state("Enabled", part=("Download restrictions", lambda x: "no special" not in str(x).lower())), "low",
         "Chrome would allow downloads flagged as dangerous.", "Enable and set to block dangerous downloads."),
]
RULES_BY_ID = {r.id: r for r in RULES}
_EXACT: dict[str, Rule] = {}
_PNAME: list[tuple[str, str, Rule]] = []
for _r in RULES:
    for _m in _r.match:
        if _m.startswith("pname:"):
            name, _, frag = _m[6:].partition("@")
            _PNAME.append((name, frag, _r))
        else:
            _EXACT[_m] = _r


def rule_for(s: Setting) -> Rule | None:
    r = _EXACT.get(s.key.lower())
    if r:
        return r
    if s.raw_type == "AdminTemplate":
        name, path = s.name.lower(), s.path.lower()
        for n, frag, rule in _PNAME:
            if n == name and (not frag or frag in path or (frag == "edge" and "microsoft edge" in path) or (frag == "chrome" and "google chrome" in path)):
                return rule
    return None


# ------------------------------------------------------------------ categorisation
_CAT_PATTERNS = [
    ("Windows Defender", r"defender antivirus|windows defender(?! firewall| smartscreen)|microsoft defender exploit|attack surface reduction"),
    ("Firewall", r"firewall"), ("Windows Update", r"windows update|delivery optimization"), ("BitLocker", r"bitlocker"),
    ("USB Restrictions", r"removable storage|device installation|autoplay"), ("RDP", r"remote desktop"),
    ("PowerShell", r"powershell"), ("Microsoft Edge", r"microsoft edge"), ("Google Chrome", r"google chrome"),
]


def category(s: Setting) -> str:
    r = rule_for(s)
    if r:
        return r.category
    if s.key.startswith("account:"):
        return {"Password": "Password Policy", "Account Lockout": "Account Lockout", "Kerberos": "Kerberos Policy"}.get(s.raw_type, "Password Policy")
    if s.raw_type in ("Audit", "AdvancedAudit"):
        return "Audit Policy"
    if s.raw_type == "UserRight":
        return "RDP" if s.path == "SeRemoteInteractiveLogonRight" else "User Rights"
    if s.raw_type in ("SecurityOption", "RestrictedGroup", "Permissions"):
        return "Security Options"
    if s.raw_type == "Service":
        return "Windows Services"
    if s.raw_type == "EventLog":
        return "Event Log"
    if s.raw_type in ("Firewall", "FirewallRule"):
        return "Firewall"
    if s.raw_type == "AdminTemplate":
        p = s.path.lower()
        for cat, rx in _CAT_PATTERNS:
            if re.search(rx, p):
                return cat
        return "Administrative Templates"
    if s.raw_type == "RegistryValue":
        p = s.path.lower()
        for cat, rx in (("Google Chrome", r"google\\chrome"), ("Microsoft Edge", r"microsoft\\edge"), ("Windows Update", r"windowsupdate"),
                        ("Windows Defender", r"windows defender"), ("PowerShell", r"powershell"), ("BitLocker", r"\\fve"),
                        ("RDP", r"terminal services")):
            if re.search(rx, p):
                return cat
        return "Administrative Templates"
    return "Preferences & Other"


def explain(s: Setting) -> str:
    if s.explain:
        return s.explain
    r = rule_for(s)
    if r:
        return r.why
    if s.raw_type == "UserRight":
        return f"Controls which accounts are granted the user right '{s.name}'."
    if s.raw_type == "Service":
        return f"Sets the startup type of the '{s.name}' service to {s.display} on computers in scope."
    if s.raw_type == "RegistryValue":
        return "Writes this registry value under the Policies key on computers/users in scope."
    if s.raw_type == "FirewallRule":
        return "A Windows Defender Firewall rule deployed by Group Policy."
    if s.raw_type == "Other":
        return f"Item from the '{s.extension}' Group Policy extension (preferences, scripts, software installation, etc.)."
    if s.raw_type == "RestrictedGroup":
        return "Enforces the membership of a local or domain group on computers in scope; other members are removed."
    return "Configured by this GPO."


# ------------------------------------------------------------------ evaluation
def evaluate(s: Setting, *, linked_at_domain_root: bool | None, section_enabled: bool, linked: bool,
             excluded: dict[str, str] | None = None) -> dict:
    r = rule_for(s)
    out = {"key": s.key, "scope": s.scope, "name": r.title if r else s.name, "report_name": s.name, "category": category(s),
           "configured_value": s.display, "expected_value": r.expected if r else "", "status": "no_baseline", "risk": "informational",
           "explanation": explain(s), "recommendation": "", "rule_id": r.id if r else None, "reference": r.ref if r else "",
           "effective": linked and section_enabled, "note": "", "path": s.path, "extension": s.extension}
    if not linked:
        out["note"] = "The GPO is not linked anywhere, so this setting does not apply to any object."
    elif not section_enabled:
        out["note"] = f"The {s.scope} settings of this GPO are disabled, so this setting is not applied."
    if r is None:
        return out
    if excluded and r.id in excluded:
        out.update(status="not_applicable", note=f"Baseline rule {r.id} excluded by an administrator: {excluded[r.id]}")
        return out
    try:
        ok = r.check(s.value)
    except Exception:  # noqa: BLE001 - unexpected value shape
        ok = None
    if r.applies == "domain_account" and linked_at_domain_root is False:
        out.update(status="not_applicable", risk="informational", effective=False,
                   note="Password, lockout and Kerberos policies only apply to domain accounts when the GPO is linked at the domain root. "
                        "Here it only affects local accounts on computers in the linked OUs.")
        if ok is False:
            out["recommendation"] = r.fix
        return out
    if not out["effective"]:
        out["status"] = "not_applicable"
        if ok is False:
            out["recommendation"] = r.fix
        return out
    if ok is None:
        out.update(status="unknown", note="The configured value could not be interpreted for the baseline comparison.")
    elif ok:
        out.update(status="compliant")
    else:
        out.update(status="non_compliant", risk=r.risk, recommendation=r.fix)
    return out
