"""Complete Group Policy report (15 sections) for administrators and management."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, GpoCollection
from app.services.gpo import knowledge as kb
from app.services.gpo import store
from app.services.reporting.render import Doc, Section, Table

SETTING_COLS = ["Policy Name", "Category", "Configured Value", "Expected Value", "Status", "Risk", "Explanation", "Recommendation"]
SETTING_W = [2.0, 1.1, 1.9, 1.5, 1.3, 1.2, 2.9, 2.3]


def _label(status: str) -> str:
    return kb.STATUS_LABEL.get(status, status)


def _risk(r: str | None) -> str:
    return (r or "informational").title()


def _setting_rows(evs: list[dict]) -> list[list]:
    rows = []
    for e in sorted(evs, key=lambda x: (kb.CATEGORIES.index(x["category"]) if x["category"] in kb.CATEGORIES else 99, x["name"])):
        expl = e["explanation"] + (f" Note: {e['note']}" if e["note"] else "")
        rows.append([e["name"], e["category"], e["configured_value"], e["expected_value"] or "-", _label(e["status"]),
                     _risk(e["risk"]) if e["status"] == "non_compliant" else "Informational", expl, e["recommendation"] or "-"])
    return rows


def _baseline_rows(rows: list[dict]) -> list[list]:
    out = []
    for b in rows:
        vals = "; ".join(f"{v['ou']}: {v['value']} ({v['gpo']})" for v in b["effective_values"][:6]) or "Not set by any GPO"
        out.append([b["title"], b["category"], vals, b["expected"], _label(b["status"]), _risk(b["risk"]) if b["status"] == "non_compliant" else "Informational",
                    b["explanation"] + (f" {b.get('note')}" if b.get("note") else ""), b["recommendation"] or "-"])
    return out


def build(db: Session, c: GpoCollection, guids: list[str] | None = None, organisation: str = "", sample: bool = False) -> Doc:
    a = store.analyse(db, c)
    inv = a.inventory()
    baseline = a.baseline()
    ov = a.overlaps()
    s = a.summary(baseline, ov)
    sel = [g for g in a.gpos if not guids or g.guid in guids]
    title = "Group Policy Report" if not guids else f"Group Policy Report - {', '.join(g.name for g in sel)[:120]}"
    doc = Doc(title=title, subtitle=f"Domain {c.domain} · collection #{c.id} ({'uploaded report' if c.source == 'upload' else 'collected from a domain controller'})",
              meta=[("Domain", c.domain), ("Data collected", c.collected_at.strftime("%Y-%m-%d %H:%M UTC")), ("Collected by", c.collected_by),
                    ("GPOs in report", len(sel)), ("Baseline", "InfraPilot baseline (CIS L1 / Microsoft Security Baseline aligned)")],
              organisation=organisation, sample=sample)
    bc = s["baseline_counts"]
    doc.kpis = [("GPOs", s["gpo_count"], ""), ("Baseline score", f"{s['baseline_score']}%" if s["baseline_score"] is not None else "n/a",
                                               "compliant" if (s["baseline_score"] or 0) >= 80 else "high"),
                ("Compliant", bc["compliant"], "compliant"), ("Non-compliant", bc["non_compliant"], "non_compliant"),
                ("Critical + high", s["non_compliant_by_risk"]["critical"] + s["non_compliant_by_risk"]["high"], "critical"),
                ("Not configured", bc["not_configured"], "not_configured"), ("Unlinked / empty", s["unlinked"] + s["empty"], "medium"),
                ("Conflicts", s["conflicts"], "medium")]

    # 1 Executive summary
    top = [b for b in baseline if b["status"] == "non_compliant"]
    top.sort(key=lambda b: kb.RISKS.index(b["risk"]))
    doc.sections.append(Section("1. Executive Summary", paragraphs=[a.executive_summary(s)],
                                bullets=[f"[{b['risk'].upper()}] {b['title']}: {next((v['value'] for v in b['effective_values'] if v['status'] == 'non_compliant'), '')} "
                                         f"(expected {b['expected']}) - {b['recommendation']}" for b in top[:8]]))
    # 2 Domain information
    di = c.domain_info or {}
    dcs = (c.extra or {}).get("domain_controllers") or []
    doc.sections.append(Section("2. Domain Information", kv=[("DNS name", di.get("dns_root") or c.domain), ("NetBIOS name", di.get("netbios", "not collected")),
                                                               ("Domain functional level", di.get("mode", "not collected")), ("Forest", di.get("forest", "not collected")),
                                                               ("PDC emulator", di.get("pdc", "not collected")), ("Precedence data", "Exact (Get-GPInheritance)" if s["exact_precedence"] else "Derived from links (approximate)")],
                                tables=[Table(["Domain controller", "Site", "IPv4", "Operating system", "Global catalog", "Read-only", "FSMO roles"],
                                              [[d.get("HostName"), d.get("Site"), d.get("IPv4Address"), d.get("OperatingSystem"), d.get("IsGlobalCatalog"),
                                                d.get("IsReadOnly"), d.get("Roles")] for d in dcs], title="Domain controllers")] if dcs else [],
                                paragraphs=[] if dcs else ["Domain controller details are available when GPOs are collected from a domain controller."]))
    # 3 Inventory
    doc.sections.append(Section("3. GPO Inventory", paragraphs=["Every GPO with its status, links and housekeeping flags (unlinked, empty, disabled, orphaned, version mismatch)."],
                                tables=[Table(["GPO", "GUID", "Status", "Owner", "Created", "Modified", "Linked to", "WMI filter", "Settings (C/U)", "Flags"],
                                              [[r["name"], r["guid"], r["status"], r["owner"], (r["created"] or "")[:10], (r["modified"] or "")[:16].replace("T", " "),
                                                "; ".join(f"{l['som_path']}{' [Enforced]' if l['enforced'] else ''}{' [Disabled]' if not l['enabled'] else ''}" for l in r["links"]) or "Not linked",
                                                r["wmi_filter"] or "-", f"{r['computer_settings']}/{r['user_settings']}", ", ".join(r["flags"]) or "-"]
                                               for r in inv if not guids or r["guid"] in guids],
                                              widths=[2, 2.2, 1.2, 1.4, 0.9, 1.1, 2.4, 1.2, 0.8, 2], sheet="GPO Inventory")]))
    # 4 Configuration details
    det = Section("4. GPO Configuration Details", paragraphs=["Each configured setting with its value, what it does, the baseline expectation and the recommendation. "
                                                             "Status distinguishes Not configured, Not applicable and Unknown from Non-compliant."])
    for g in sorted(sel, key=lambda x: x.name.lower()):
        r = next(x for x in inv if x["guid"] == g.guid)
        evs = a.settings[g.guid]
        sec = Section(g.name, kv=[("GUID", g.guid), ("Status", g.status), ("Links", "; ".join(l["som_path"] for l in r["links"]) or "Not linked"),
                                  ("Owner", g.owner or "-"), ("Modified", g.modified or "-"), ("Security filtering", ", ".join(g.security_filtering) or "-"),
                                  ("Flags", ", ".join(r["flags"]) or "-")])
        if not evs:
            sec.paragraphs.append("This GPO contains no settings.")
        for scope, label in (("computer", "Computer Configuration"), ("user", "User Configuration")):
            rows = _setting_rows([e for e in evs if e["scope"] == scope])
            if rows:
                sec.tables.append(Table(SETTING_COLS, rows, title=label, widths=SETTING_W, sheet=f"{g.name[:20]} {'C' if scope == 'computer' else 'U'}"))
        det.children.append(sec)
    doc.sections.append(det)
    # 5-7 baseline by group
    groups = list(kb.REPORT_GROUPS.items())
    for num, (gname, cats) in zip((5, 6, 7), groups[:3]):
        rows = [b for b in baseline if b["category"] in cats]
        doc.sections.append(Section(f"{num}. {gname}", paragraphs=["Effective values per OU (winning GPO by precedence) compared with the baseline."],
                                    tables=[Table(["Policy Name", "Category", "Configured Value", "Expected Value", "Status", "Risk", "Explanation", "Recommendation"],
                                                  _baseline_rows(rows), widths=SETTING_W, sheet=gname[:28])]))
    # 8 user and computer configuration
    doc.sections.append(Section("8. User and Computer Configuration", paragraphs=[
        "Computer settings apply to computer objects in the linked OUs at start-up and refresh; user settings apply to user objects at sign-in. "
        "Disabling one half of a GPO speeds up processing when it has no settings."],
        tables=[Table(["GPO", "Computer section", "Computer settings", "User section", "User settings", "Observation"],
                      [[g.name, "Enabled" if g.computer_enabled else "Disabled", sum(1 for x in g.settings if x.scope == "computer"),
                        "Enabled" if g.user_enabled else "Disabled", sum(1 for x in g.settings if x.scope == "user"),
                        _half_note(g)] for g in sorted(sel, key=lambda x: x.name.lower())], sheet="Computer-User")]))
    # 9 links and inheritance
    prec_rows = []
    for p in a.ou_paths():
        for x in a.precedence(p):
            prec_rows.append([a.display_path(p), x["precedence"], x["name"], "Yes" if x["enforced"] else "No",
                              "Yes" if a._ou.get(p, {}).get("blocked") else ("No" if a._ou else "Unknown"), x["source"]])
    doc.sections.append(Section("9. OU Links and Inheritance", paragraphs=[
        "For each OU, the GPOs that apply in precedence order (1 wins). Enforced links override block inheritance and lower links."],
        tables=[Table(["OU / container", "Precedence", "GPO", "Enforced", "Block inheritance on OU", "Source"], prec_rows, widths=[3, 0.8, 2.5, 0.8, 1.2, 1.6], sheet="Precedence")]))
    # 10 conflicts and duplicates
    doc.sections.append(Section("10. Conflicting and Duplicate Settings", tables=[
        Table(["Setting", "Category", "OU(s)", "Values by GPO (precedence order)", "Effective (winner)", "Explanation"],
              [[x["name"], x["category"], ", ".join(x["ous"]), "; ".join(f"{g['name']}: {g['value']}" for g in x["gpos"]), x["winner"], x["explanation"]]
               for x in ov["conflicts"]], title="Conflicts (same OU, different values)", sheet="Conflicts"),
        Table(["Setting", "Category", "OU(s)", "GPOs", "Value", "Explanation"],
              [[x["name"], x["category"], ", ".join(x["ous"]), ", ".join(g["name"] for g in x["gpos"]), x["value"], x["explanation"]] for x in ov["duplicates"]],
              title="Duplicates (same OU, same value)", sheet="Duplicates"),
        Table(["Setting", "Category", "Effective value per OU"], [[x["name"], x["category"], "; ".join(f"{v['ou']}: {v['value']} ({v['gpo']})" for v in x["values"])]
                                                                for x in ov["ou_differences"]], title="Settings configured differently across OUs", sheet="OU differences")]))
    # 11 missing or weak
    weak = [b for b in baseline if b["status"] in ("non_compliant", "unknown")]
    missing = [b for b in baseline if b["status"] == "not_configured"]
    doc.sections.append(Section("11. Missing or Weak Security Configurations", paragraphs=[
        "Weak = configured but below the baseline. Missing = no GPO sets it; verify locally (e.g. with gpresult or a configuration scan) before treating it as a gap."],
        tables=[Table(["Policy Name", "Category", "Configured Value", "Expected Value", "Status", "Risk", "Explanation", "Recommendation"], _baseline_rows(weak),
                      title="Weak configurations", widths=SETTING_W, sheet="Weak"),
                Table(["Policy Name", "Category", "Expected Value", "Status", "Baseline risk if absent", "Recommendation"],
                      [[b["title"], b["category"], b["expected"], "Not configured", kb.RULES_BY_ID[b["rule_id"]].risk.title(), kb.RULES_BY_ID[b["rule_id"]].fix] for b in missing],
                      title="Not configured by Group Policy", sheet="Not configured")]))
    # 12 risk classification
    doc.sections.append(Section("12. Risk Classification", tables=[Table(["Risk", "Non-compliant items", "Meaning"], [
        ["Critical", s["non_compliant_by_risk"]["critical"], "Directly disables a core protection or exposes credentials; fix immediately."],
        ["High", s["non_compliant_by_risk"]["high"], "Significantly increases the chance or impact of compromise; fix within 30 days."],
        ["Medium", s["non_compliant_by_risk"]["medium"], "Weakens defence in depth or detection; plan remediation."],
        ["Low", s["non_compliant_by_risk"]["low"], "Hardening improvement with limited impact."],
        ["Informational", bc["compliant"] + bc["no_baseline"], "Compliant or no baseline expectation."]])]))
    # 13 recommendations
    rec_rows = []
    for b in top:
        gpos = ", ".join(sorted({v["gpo"] for v in b["effective_values"] if v["status"] == "non_compliant"})) or ", ".join(x["name"] for x in b["gpos"])
        rec_rows.append([b["risk"].title(), b["title"], gpos, b["expected"], b["recommendation"], b["reference"]])
    for x in ov["conflicts"]:
        rec_rows.append(["Low", f"Conflict: {x['name']}", ", ".join(g["name"] for g in x["gpos"]), "One authoritative GPO",
                         "Remove the setting from the GPOs that lose by precedence to avoid confusion.", "Hygiene"])
    for r in inv:
        if r["flags"] and (not guids or r["guid"] in guids):
            rec_rows.append(["Low", f"Housekeeping: {r['name']}", r["name"], "-", _hygiene_fix(r["flags"]), "Hygiene"])
    doc.sections.append(Section("13. Recommendations and Remediation", paragraphs=[
        "Test every change in a pilot OU first; use the GPO Backup and Restore page to back up a GPO before editing it."],
        tables=[Table(["Risk", "Item", "GPO(s) to change", "Target", "Recommendation", "Reference"], rec_rows, widths=[0.8, 2.4, 2, 1.6, 4, 1.4], sheet="Recommendations")]))
    # 14 history
    hist = db.execute(select(GpoCollection).where(GpoCollection.domain == c.domain, GpoCollection.id <= c.id).order_by(GpoCollection.id.desc()).limit(30)).scalars().all()
    hrows = []
    for h in hist:
        ch = (h.extra or {}).get("changed") or []
        dl = (h.extra or {}).get("deleted") or []
        hrows.append([h.collected_at, f"#{h.id}", h.source, h.gpo_count, len(ch) + len(dl),
                      "; ".join([("New: " if x.get("new") else "Changed: ") + x["name"] for x in ch][:15] + ["Deleted: " + x["name"] for x in dl][:10]) or "-"])
    doc.sections.append(Section("14. Historical Changes", paragraphs=["Collections of this domain and the GPOs that changed between them. "
                                                                      "Open Group Policy → History in InfraPilot for a setting-level before/after comparison."],
                                tables=[Table(["Collected", "Collection", "Source", "GPOs", "Changed/deleted", "Details"], hrows, widths=[1.3, 0.8, 0.8, 0.6, 0.9, 6], sheet="History")]))
    # 15 audit trail
    aud = db.execute(select(AuditLog).where(AuditLog.action.like("gpo.%")).order_by(AuditLog.id.desc()).limit(200)).scalars().all()
    doc.sections.append(Section("15. Audit Trail", paragraphs=["Group Policy actions recorded in InfraPilot's tamper-evident audit log (most recent 200)."],
                                tables=[Table(["Time", "Actor", "Action", "Target", "Result", "Details"],
                                              [[x.ts, x.actor_name, x.action, x.target_name, x.result, ", ".join(f"{k}={v}" for k, v in (x.details or {}).items())[:300]]
                                               for x in aud if not x.target_id or x.target_type != "domain" or x.target_id == c.domain], sheet="Audit trail")]))
    return doc


def _half_note(g) -> str:
    cs = sum(1 for x in g.settings if x.scope == "computer")
    us = sum(1 for x in g.settings if x.scope == "user")
    if g.computer_enabled and not cs and us:
        return "Computer half is empty - consider disabling it"
    if g.user_enabled and not us and cs:
        return "User half is empty - consider disabling it"
    if not g.computer_enabled and cs:
        return "Computer settings exist but the half is disabled - they do not apply"
    if not g.user_enabled and us:
        return "User settings exist but the half is disabled - they do not apply"
    return "-"


def _hygiene_fix(flags: list[str]) -> str:
    tips = []
    for f in flags:
        if f == "Unlinked":
            tips.append("Link it where needed or back it up and delete it")
        elif f == "Empty (no settings)":
            tips.append("Delete the empty GPO")
        elif f.startswith("Version mismatch"):
            tips.append("Check SYSVOL/DFSR replication health (dcdiag /test:sysvolcheck)")
        elif f.startswith("Orphaned"):
            tips.append("Remove the orphaned AD object or SYSVOL folder after backing it up")
        elif f == "All settings disabled":
            tips.append("Delete or re-enable the GPO")
        elif f == "All links disabled":
            tips.append("Remove disabled links or delete the GPO")
        elif f.startswith("No security filtering"):
            tips.append("Grant Apply Group Policy to the intended group")
    return "; ".join(tips) or "Review"
