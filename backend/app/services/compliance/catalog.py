"""Built-in compliance frameworks and control mappings.

Control titles follow the public structure of each framework; descriptions are InfraPilot's own summaries,
not the licensed text. Mappings connect controls to InfraPilot's automated checks, which only ever produce
evidence for the technical part of a control - process, policy and people aspects always need an auditor's
assessment. Nothing here certifies compliance.

The RBI set lists the baseline technical controls of the RBI Cyber Security Framework for banks (2016,
Annex 1) together with related expectations from the RBI Master Direction on IT Governance, Risk, Controls
and Assurance Practices (2023). Confirm which requirements apply to your regulated activities and mark the
others "Not applicable" in the assessment.
"""
from __future__ import annotations

C = tuple  # (ref, domain, title, description, [check keys])

FRAMEWORKS: dict[str, dict] = {
    "ISO27001-2022": {
        "name": "ISO/IEC 27001:2022 - Annex A (technological and selected organisational controls)", "version": "2022",
        "description": "Information security management system controls. Only controls with an IT-infrastructure component are listed; "
                       "add the remaining Annex A controls as custom controls if this assessment covers the whole ISMS.",
        "controls": [
            C(("A.5.9", "Organizational", "Inventory of information and other associated assets", "An inventory of assets, with owners, is developed and maintained.", ["asset_inventory"])),
            C(("A.5.15", "Organizational", "Access control", "Rules to control physical and logical access are established based on business and security requirements.", ["ad_privileged", "gpo_remote_access"])),
            C(("A.5.16", "Organizational", "Identity management", "The full life cycle of identities is managed.", ["ad_inactive_users", "ad_stale_computers"])),
            C(("A.5.17", "Organizational", "Authentication information", "Allocation and management of authentication information is controlled.", ["ad_password_policy", "gpo_password", "ad_risky_accounts"])),
            C(("A.5.18", "Organizational", "Access rights", "Access rights are provisioned, reviewed, modified and removed in line with policy.", ["ad_inactive_users", "ad_privileged"])),
            C(("A.5.24", "Organizational", "Information security incident management planning and preparation", "Incident management processes, roles and responsibilities are defined.", [])),
            C(("A.5.30", "Organizational", "ICT readiness for business continuity", "ICT readiness is planned, implemented, maintained and tested.", ["backup_offsite"])),
            C(("A.8.1", "Technological", "User end point devices", "Information on, processed by or accessible via user endpoint devices is protected.", ["gpo_malware", "gpo_host_firewall", "gpo_removable_media"])),
            C(("A.8.2", "Technological", "Privileged access rights", "The allocation and use of privileged access rights is restricted and managed.", ["ad_privileged", "platform_mfa"])),
            C(("A.8.5", "Technological", "Secure authentication", "Secure authentication technologies and procedures are implemented.", ["gpo_password", "ad_password_policy", "platform_mfa", "linux_ssh"])),
            C(("A.8.7", "Technological", "Protection against malware", "Protection against malware is implemented and supported by user awareness.", ["gpo_malware"])),
            C(("A.8.8", "Technological", "Management of technical vulnerabilities", "Information about vulnerabilities is obtained, exposure evaluated and measures taken.", ["patch_status", "gpo_updates"])),
            C(("A.8.9", "Technological", "Configuration management", "Configurations, including security configurations, are established, documented, monitored and reviewed.", ["gpo_baseline", "config_backup", "linux_ssh"])),
            C(("A.8.13", "Technological", "Information backup", "Backup copies of information, software and systems are maintained and regularly tested.", ["config_backup", "backup_offsite"])),
            C(("A.8.15", "Technological", "Logging", "Logs recording activities, exceptions, faults and other relevant events are produced, stored, protected and analysed.", ["gpo_audit", "audit_trail"])),
            C(("A.8.16", "Technological", "Monitoring activities", "Networks, systems and applications are monitored for anomalous behaviour.", ["monitoring_coverage"])),
            C(("A.8.18", "Technological", "Use of privileged utility programs", "Use of utility programs that can override system and application controls is restricted.", ["gpo_baseline"])),
            C(("A.8.19", "Technological", "Installation of software on operational systems", "Procedures and measures are implemented to securely manage software installation.", ["software_inventory"])),
            C(("A.8.20", "Technological", "Networks security", "Networks and network devices are secured, managed and controlled.", ["firewall_rules", "config_backup"])),
            C(("A.8.21", "Technological", "Security of network services", "Security mechanisms, service levels and requirements of network services are identified and implemented.", ["gpo_remote_access", "linux_ssh"])),
            C(("A.8.22", "Technological", "Segregation of networks", "Groups of information services, users and systems are segregated in networks.", [])),
            C(("A.8.24", "Technological", "Use of cryptography", "Rules for the effective use of cryptography are defined and implemented.", ["gpo_remote_access"])),
            C(("A.8.32", "Technological", "Change management", "Changes to information processing facilities and systems are subject to change management procedures.", ["change_control", "audit_trail"])),
        ],
    },
    "CIS-V8": {
        "name": "CIS Critical Security Controls v8 and CIS Benchmarks (Windows/GPO)", "version": "8.1",
        "description": "Selected Implementation Group 1/2 safeguards. Windows configuration items are assessed against the InfraPilot GPO baseline, "
                       "which is aligned with the CIS Microsoft Windows Server Benchmark Level 1.",
        "controls": [
            C(("1.1", "Inventory and Control of Enterprise Assets", "Establish and maintain a detailed enterprise asset inventory", "Accurate, up-to-date inventory of all enterprise assets.", ["asset_inventory"])),
            C(("2.1", "Inventory and Control of Software Assets", "Establish and maintain a software inventory", "Inventory of installed software on servers.", ["software_inventory"])),
            C(("4.1", "Secure Configuration", "Establish and maintain a secure configuration process", "Documented secure configuration baselines, applied and monitored.", ["gpo_baseline", "linux_ssh"])),
            C(("4.4", "Secure Configuration", "Implement and manage a firewall on servers", "Host-based firewall enabled with default-deny.", ["gpo_host_firewall"])),
            C(("4.5", "Secure Configuration", "Implement and manage a firewall on end-user devices", "Host-based firewall enabled with default-deny on end-user devices.", ["gpo_host_firewall"])),
            C(("4.7", "Secure Configuration", "Manage default accounts on enterprise assets", "Default accounts (Guest, built-in Administrator) disabled or managed.", ["gpo_baseline"])),
            C(("5.1", "Account Management", "Establish and maintain an inventory of accounts", "Inventory of all user and administrator accounts.", ["ad_inactive_users"])),
            C(("5.2", "Account Management", "Use unique passwords", "Unique, strong passwords for all accounts.", ["ad_password_policy", "gpo_password"])),
            C(("5.3", "Account Management", "Disable dormant accounts", "Delete or disable accounts after 45 days of inactivity.", ["ad_inactive_users"])),
            C(("5.4", "Account Management", "Restrict administrator privileges to dedicated administrator accounts", "Administrator rights only on dedicated admin accounts.", ["ad_privileged"])),
            C(("6.5", "Access Control Management", "Require MFA for administrative access", "MFA for all administrative access.", ["platform_mfa"])),
            C(("7.3", "Continuous Vulnerability Management", "Perform automated operating system patch management", "OS updates applied on a regular automated schedule.", ["patch_status", "gpo_updates"])),
            C(("8.2", "Audit Log Management", "Collect audit logs", "Audit logging enabled across enterprise assets.", ["gpo_audit", "audit_trail"])),
            C(("10.1", "Malware Defenses", "Deploy and maintain anti-malware software", "Anti-malware on all enterprise assets.", ["gpo_malware"])),
            C(("10.3", "Malware Defenses", "Disable autorun and autoplay for removable media", "AutoRun/AutoPlay disabled.", ["gpo_removable_media"])),
            C(("11.2", "Data Recovery", "Perform automated backups", "Automated backups of in-scope assets.", ["config_backup", "backup_offsite"])),
            C(("12.1", "Network Infrastructure Management", "Ensure network infrastructure is up to date", "Network devices run supported, current firmware and their configuration is managed.", ["config_backup"])),
            C(("13.1", "Network Monitoring and Defense", "Centralize security event alerting", "Security events correlated and alerted centrally.", ["monitoring_coverage"])),
            C(("13.4", "Network Monitoring and Defense", "Perform traffic filtering between network segments", "Filtering between network segments.", ["firewall_rules"])),
        ],
    },
    "NIST-CSF-2.0": {
        "name": "NIST Cybersecurity Framework 2.0", "version": "2.0",
        "description": "Outcome-based subcategories relevant to IT infrastructure operations.",
        "controls": [
            C(("ID.AM-01", "Identify / Asset Management", "Inventories of hardware managed by the organization are maintained", "", ["asset_inventory"])),
            C(("ID.AM-02", "Identify / Asset Management", "Inventories of software, services and systems are maintained", "", ["software_inventory"])),
            C(("ID.RA-01", "Identify / Risk Assessment", "Vulnerabilities in assets are identified, validated and recorded", "", ["patch_status"])),
            C(("PR.AA-01", "Protect / Identity Management, Authentication, and Access Control", "Identities and credentials for authorized users, services and hardware are managed", "", ["ad_inactive_users", "ad_password_policy", "ad_risky_accounts"])),
            C(("PR.AA-03", "Protect / Identity Management, Authentication, and Access Control", "Users, services and hardware are authenticated", "", ["gpo_password", "platform_mfa", "linux_ssh"])),
            C(("PR.AA-05", "Protect / Identity Management, Authentication, and Access Control", "Access permissions, entitlements and authorizations are defined, managed and reviewed (least privilege)", "", ["ad_privileged"])),
            C(("PR.DS-11", "Protect / Data Security", "Backups of data are created, protected, maintained and tested", "", ["config_backup", "backup_offsite"])),
            C(("PR.PS-01", "Protect / Platform Security", "Configuration management practices are established and applied", "", ["gpo_baseline", "config_backup", "linux_ssh"])),
            C(("PR.PS-02", "Protect / Platform Security", "Software is maintained, replaced and removed commensurate with risk", "", ["patch_status", "gpo_updates"])),
            C(("PR.PS-04", "Protect / Platform Security", "Log records are generated and made available for continuous monitoring", "", ["gpo_audit", "audit_trail"])),
            C(("PR.PS-05", "Protect / Platform Security", "Installation and execution of unauthorized software are prevented", "", ["gpo_malware", "gpo_removable_media"])),
            C(("PR.IR-01", "Protect / Technology Infrastructure Resilience", "Networks and environments are protected from unauthorized logical access and usage", "", ["firewall_rules", "gpo_host_firewall", "gpo_remote_access"])),
            C(("DE.CM-01", "Detect / Continuous Monitoring", "Networks and network services are monitored to find potentially adverse events", "", ["monitoring_coverage"])),
            C(("DE.CM-09", "Detect / Continuous Monitoring", "Computing hardware and software, runtime environments and their data are monitored", "", ["monitoring_coverage", "gpo_malware"])),
            C(("GV.OV-01", "Govern / Oversight", "Cybersecurity risk management strategy outcomes are reviewed", "", [])),
            C(("PR.PS-03", "Protect / Platform Security", "Hardware is maintained, replaced and removed commensurate with risk", "", [])),
            C(("RS.MA-01", "Respond / Incident Management", "The incident response plan is executed in coordination with relevant third parties", "", [])),
            C(("RC.RP-01", "Recover / Incident Recovery Plan Execution", "The recovery portion of the incident response plan is executed", "", ["backup_offsite"])),
            C(("ID.IM-02", "Identify / Improvement", "Improvements are identified from security tests and exercises", "", ["change_control"])),
        ],
    },
    "RBI-CSF": {
        "name": "RBI Cyber Security Framework - baseline controls (with IT Governance Master Direction 2023)", "version": "2016 / 2023",
        "description": "Baseline technical controls applicable to RBI-regulated entities. Confirm applicability for your regulated activities; "
                       "customer-facing and fraud controls are listed for completeness and normally need manual evidence.",
        "controls": [
            C(("CSF-1", "Annex 1 baseline", "Inventory management of business IT assets", "Maintain an up-to-date inventory of business IT assets with owners and classification.", ["asset_inventory", "software_inventory"])),
            C(("CSF-2", "Annex 1 baseline", "Preventing execution of unauthorised software", "Allow-list authorised software and prevent unauthorised software installation.", ["software_inventory", "gpo_removable_media"])),
            C(("CSF-3", "Annex 1 baseline", "Environmental controls", "Physical and environmental protection of data centres and critical equipment.", [])),
            C(("CSF-4", "Annex 1 baseline", "Network management and security", "Network segmentation, perimeter controls, firewall rule review and secure device management.", ["firewall_rules", "config_backup"])),
            C(("CSF-5", "Annex 1 baseline", "Secure configuration", "Documented hardening baselines for systems and periodic verification.", ["gpo_baseline", "linux_ssh"])),
            C(("CSF-6", "Annex 1 baseline", "Application security life cycle", "Security across the application development and change life cycle.", [])),
            C(("CSF-7", "Annex 1 baseline", "Patch / vulnerability and change management", "Timely patching, vulnerability management and controlled change management.", ["patch_status", "gpo_updates", "change_control"])),
            C(("CSF-8", "Annex 1 baseline", "User access control / management", "Least privilege, periodic access review, prompt removal of inactive or leaver accounts, controlled privileged access.", ["ad_privileged", "ad_inactive_users", "ad_stale_computers", "platform_mfa"])),
            C(("CSF-9", "Annex 1 baseline", "Authentication framework for customers", "Strong authentication for customer channels.", [])),
            C(("CSF-12", "Annex 1 baseline", "Removable media", "Control and monitor use of removable media.", ["gpo_removable_media"])),
            C(("CSF-13", "Annex 1 baseline", "Advanced real-time threat defence and management", "Anti-malware and endpoint protection with central management.", ["gpo_malware", "gpo_host_firewall"])),
            C(("CSF-16", "Annex 1 baseline", "Maintenance, monitoring and analysis of audit logs", "Collect, retain and review audit logs; protect them from tampering.", ["audit_trail", "monitoring_coverage"])),
            C(("CSF-17", "Annex 1 baseline", "Audit log settings", "Enable audit logging for security-relevant events on all systems.", ["gpo_audit"])),
            C(("CSF-18", "Annex 1 baseline", "Vulnerability assessment, penetration testing and red team exercises", "Periodic VA/PT of critical systems with remediation tracking.", ["patch_status"])),
            C(("CSF-19", "Annex 1 baseline", "Incident response and management", "Documented incident response with timely reporting to RBI where required.", [])),
            C(("ITGOV-BCP", "IT Governance MD 2023", "Business continuity and disaster recovery", "Backups, DR drills and recovery objectives for critical systems.", ["backup_offsite", "config_backup"])),
            C(("ITGOV-PWD", "IT Governance MD 2023", "Password and authentication controls", "Strong password policies and account lockout for internal users.", ["ad_password_policy", "gpo_password", "ad_risky_accounts"])),
        ],
    },
}


def seed(db) -> None:
    """Idempotently create/refresh the built-in frameworks (custom controls added by users are kept)."""
    from sqlalchemy import select

    from app.models import ComplianceControl, ComplianceFramework
    for code, f in FRAMEWORKS.items():
        fw = db.execute(select(ComplianceFramework).where(ComplianceFramework.code == code)).scalar_one_or_none()
        if fw is None:
            fw = ComplianceFramework(code=code, name=f["name"], version=f["version"], description=f["description"], is_builtin=True)
            db.add(fw)
            db.flush()
        else:
            fw.name, fw.version, fw.description = f["name"], f["version"], f["description"]
        have = {c.ref: c for c in db.execute(select(ComplianceControl).where(ComplianceControl.framework_id == fw.id)).scalars().all()}
        for i, (ref, domain, title, desc, checks) in enumerate(f["controls"]):
            c = have.get(ref)
            if c is None:
                db.add(ComplianceControl(framework_id=fw.id, ref=ref, domain=domain, title=title, description=desc, check_keys=checks, sort=i))
            else:
                c.domain, c.title, c.description, c.check_keys, c.sort = domain, title, desc, checks, i
    db.flush()
