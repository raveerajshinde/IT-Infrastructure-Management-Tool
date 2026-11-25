"""GPO analysis: inventory classification, precedence per OU, conflicts/duplicates, baseline assessment, comparisons.

Precedence follows Group Policy processing rules:
  1. Enforced links win over everything; among enforced links the one highest in the tree (domain) wins.
  2. Otherwise the link closest to the OU wins (OU > parent OU > domain); within one container, link order 1 wins.
  3. "Block inheritance" on an OU stops non-enforced links from parent containers.
When the collector provided Get-GPInheritance data (collection from a domain controller) that exact order is used.
For uploaded XML reports link order and block inheritance are not in the file, so the order is derived from the
links in the report and flagged as approximate.
Site-linked GPOs are listed but not included in OU precedence (they depend on the computer's AD site).
"""
from __future__ import annotations

import json
from collections import defaultdict

from app.services.gpo import knowledge as kb
from app.services.gpo.parser import Gpo, Setting

RISK_ORDER = {r: i for i, r in enumerate(kb.RISKS)}


def _vkey(v) -> str:
    return json.dumps(v, sort_keys=True, default=str)


def _ancestors(path: str, root: str) -> list[str]:
    """corp.local/A/B -> [corp.local, corp.local/A, corp.local/A/B] (top-down)."""
    if not path.lower().startswith(root.lower()):
        return [path]
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]


class Analysis:
    def __init__(self, gpos: list[Gpo], domain: str, domain_info: dict | None = None, ou_data: list | None = None,
                 extra: dict | None = None, excluded: dict[str, str] | None = None):
        self.gpos = gpos
        self.by_guid = {g.guid: g for g in gpos}
        self.domain = domain or (gpos[0].domain if gpos else "")
        self.domain_info = domain_info or {}
        self.root = (self.domain_info.get("dns_root") or self.domain).lower()
        self.ou_data = ou_data or []
        self.extra = extra or {}
        self.excluded = excluded or {}
        self.exact_precedence = any(o.get("inherited") is not None for o in self.ou_data)
        self._ou = {o["path"].lower(): o for o in self.ou_data if o.get("path")}
        self.links_at: dict[str, list[tuple[str, bool, bool, int]]] = defaultdict(list)   # path -> [(guid, enforced, enabled, order)]
        for g in gpos:
            for i, l in enumerate(g.links):
                order = next((x.get("order") for o in [self._ou.get(l.som_path.lower(), {})] for x in o.get("links", [])
                              if x.get("guid") == g.guid), None) or 100 + i
                self.links_at[l.som_path.lower()].append((g.guid, l.enforced, l.enabled, order))
        for v in self.links_at.values():
            v.sort(key=lambda t: t[3])
        self.settings = {g.guid: self._evaluate(g) for g in gpos}

    # ------------------------------------------------------------ helpers
    def is_site(self, som_path: str) -> bool:
        return not som_path.lower().startswith(self.root) if self.root else False

    def linked_at_root(self, g: Gpo) -> bool:
        return any(l.som_path.lower() == self.root and l.enabled for l in g.links)

    def linked(self, g: Gpo) -> bool:
        return any(l.enabled for l in g.links)

    def ou_paths(self) -> list[str]:
        paths = {self.root} | {p for p in self.links_at if not self.is_site(p)} | set(self._ou)
        return sorted(paths, key=lambda p: (p.count("/"), p))

    def display_path(self, p: str) -> str:
        if p == self.root:
            return f"{self.domain_info.get('dns_root') or self.domain} (domain root, incl. default Computers/Users containers)"
        o = self._ou.get(p)
        if o and p != self.root:
            return o["path"]
        for g in self.gpos:
            for l in g.links:
                if l.som_path.lower() == p:
                    return l.som_path
        if p == self.root:
            return f"{self.domain_info.get('dns_root') or self.domain} (domain root, incl. default Computers/Users containers)"
        return p

    def _evaluate(self, g: Gpo) -> list[dict]:
        root = self.linked_at_root(g)
        linked = self.linked(g)
        out = []
        for s in g.settings:
            ev = kb.evaluate(s, linked_at_domain_root=root, section_enabled=g.computer_enabled if s.scope == "computer" else g.user_enabled,
                             linked=linked, excluded=self.excluded)
            out.append(ev)
        return out

    def precedence(self, path: str) -> list[dict]:
        """GPOs applying to an OU (or the domain root) in precedence order (1 = wins)."""
        p = path.lower()
        o = self._ou.get(p)
        if o and o.get("inherited") is not None:
            res = []
            for i, guid in enumerate(o["inherited"]):
                g = self.by_guid.get(str(guid).lower().strip("{}"))
                if g:
                    res.append({"guid": g.guid, "name": g.name, "precedence": i + 1,
                                "enforced": any(l.enforced for l in g.links), "source": "Get-GPInheritance"})
            return res
        chain = _ancestors(p, self.root)
        blocked_at = max((i for i, a in enumerate(chain) if self._ou.get(a, {}).get("blocked")), default=-1)
        enforced, normal = [], []
        for i, a in enumerate(chain):
            for guid, enf, enabled, _order in self.links_at.get(a, []):
                if not enabled:
                    continue
                (enforced if enf else normal).append((i, guid))
        res, seen = [], set()
        for _i, guid in sorted(enforced, key=lambda t: t[0]):                         # top-down
            if guid not in seen:
                seen.add(guid)
                res.append(guid)
        for i, guid in sorted(normal, key=lambda t: -t[0]):                            # closest first
            if i < blocked_at or guid in seen:
                continue
            seen.add(guid)
            res.append(guid)
        return [{"guid": g, "name": self.by_guid[g].name, "precedence": n + 1, "enforced": any(l.enforced for l in self.by_guid[g].links),
                 "source": "derived from links (approximate)"} for n, g in enumerate(res)]

    def _setting_map(self, g: Gpo) -> dict[str, Setting]:
        return {f"{s.scope}|{s.key}": s for s in g.settings if (g.computer_enabled if s.scope == "computer" else g.user_enabled)}

    # ------------------------------------------------------------ inventory
    def inventory(self) -> list[dict]:
        sysvol_missing = {x.lower() for x in self.extra.get("sysvol_missing", [])}
        rows = []
        for g in sorted(self.gpos, key=lambda x: x.name.lower()):
            flags = []
            if not g.links:
                flags.append("Unlinked")
            elif not self.linked(g):
                flags.append("All links disabled")
            if not g.computer_enabled and not g.user_enabled:
                flags.append("All settings disabled")
            if not g.settings:
                flags.append("Empty (no settings)")
            cdir, csys = g.computer_version.split("/")
            udir, usys = g.user_version.split("/")
            if cdir != csys or udir != usys:
                flags.append("Version mismatch AD/SYSVOL")
            if g.guid in sysvol_missing:
                flags.append("Orphaned (SYSVOL folder missing)")
            if self.extra.get("security_filtering_known", True) and g.xml and not g.security_filtering and "TrusteePermissions" in g.xml:
                flags.append("No security filtering (applies to no one)")
            if g.computer_enabled and not any(s.scope == "computer" for s in g.settings) and any(s.scope == "user" for s in g.settings):
                flags.append("Computer side enabled but empty")
            ev = self.settings[g.guid]
            rows.append({"guid": g.guid, "name": g.name, "domain": g.domain, "status": g.status, "created": g.created, "modified": g.modified,
                         "owner": g.owner, "wmi_filter": g.wmi_filter,
                         "links": [{"som_name": l.som_name, "som_path": l.som_path, "enabled": l.enabled, "enforced": l.enforced,
                                    "site": self.is_site(l.som_path)} for l in g.links],
                         "linked": self.linked(g), "linked_at_root": self.linked_at_root(g), "flags": flags,
                         "unused": (not self.linked(g)) or not g.settings or (not g.computer_enabled and not g.user_enabled),
                         "computer_settings": sum(1 for s in g.settings if s.scope == "computer"),
                         "user_settings": sum(1 for s in g.settings if s.scope == "user"),
                         "computer_version": g.computer_version, "user_version": g.user_version,
                         "security_filtering": g.security_filtering,
                         "non_compliant": sum(1 for e in ev if e["status"] == "non_compliant"),
                         "worst_risk": min((e["risk"] for e in ev if e["status"] == "non_compliant"), key=lambda r: RISK_ORDER[r], default=None)})
        for orphan in self.extra.get("sysvol_orphans", []):
            rows.append({"guid": orphan.lower(), "name": f"(SYSVOL folder without AD object) {orphan}", "domain": self.domain, "status": "Orphaned",
                         "created": None, "modified": None, "owner": "", "wmi_filter": "", "links": [], "linked": False, "linked_at_root": False,
                         "flags": ["Orphaned (no AD object)"], "unused": True, "computer_settings": 0, "user_settings": 0, "computer_version": "",
                         "user_version": "", "security_filtering": [], "non_compliant": 0, "worst_risk": None})
        return rows

    # ------------------------------------------------------------ conflicts, duplicates, differences across OUs
    def overlaps(self) -> dict:
        maps = {g.guid: self._setting_map(g) for g in self.gpos}
        conflicts: dict[tuple, dict] = {}
        duplicates: dict[tuple, dict] = {}
        winners: dict[str, dict[str, tuple[str, str, str]]] = defaultdict(dict)  # setting -> path -> (guid, valuekey, display)
        for path in self.ou_paths():
            order = [x["guid"] for x in self.precedence(path)]
            by_key: dict[str, list[tuple[str, Setting]]] = defaultdict(list)
            for guid in order:
                for k, s in maps.get(guid, {}).items():
                    by_key[k].append((guid, s))
            for k, lst in by_key.items():
                win_guid, win_s = lst[0]
                winners[k][path] = (win_guid, _vkey(win_s.value), win_s.display)
                if len(lst) < 2:
                    continue
                vals = {_vkey(s.value) for _, s in lst}
                ident = (k, tuple(sorted(g for g, _ in lst)))
                rec = {"setting_key": k.split("|", 1)[1], "scope": k.split("|", 1)[0], "name": kb.rule_for(win_s).title if kb.rule_for(win_s) else win_s.name,
                       "category": kb.category(win_s),
                       "gpos": [{"guid": g, "name": self.by_guid[g].name, "value": s.display, "wins": i == 0} for i, (g, s) in enumerate(lst)]}
                if len(vals) > 1:
                    c = conflicts.setdefault(ident, {**rec, "ous": [], "winner": self.by_guid[win_guid].name,
                                                     "explanation": f"Configured with different values; '{self.by_guid[win_guid].name}' wins by precedence."})
                    c["ous"].append(self.display_path(path))
                else:
                    d = duplicates.setdefault(ident, {**rec, "ous": [], "value": win_s.display,
                                                      "explanation": "The same value is set by several GPOs that apply to the same OU; all but one are redundant."})
                    d["ous"].append(self.display_path(path))
        differences = []
        for k, per in winners.items():
            if len({v[1] for v in per.values()}) > 1:
                any_s = next(s for g in self.gpos for kk, s in maps[g.guid].items() if kk == k)
                r = kb.rule_for(any_s)
                differences.append({"setting_key": k.split("|", 1)[1], "scope": k.split("|", 1)[0], "name": r.title if r else any_s.name,
                                    "category": kb.category(any_s),
                                    "values": [{"ou": self.display_path(p), "gpo": self.by_guid[v[0]].name, "value": v[2]} for p, v in sorted(per.items())]})
        return {"conflicts": list(conflicts.values()), "duplicates": list(duplicates.values()),
                "ou_differences": sorted(differences, key=lambda d: (d["category"], d["name"])), "exact_precedence": self.exact_precedence}

    # ------------------------------------------------------------ baseline
    def baseline(self) -> list[dict]:
        maps = {g.guid: self._setting_map(g) for g in self.gpos}
        precedence = {p: [x["guid"] for x in self.precedence(p)] for p in self.ou_paths()}
        out = []
        for r in kb.RULES:
            configured = []
            for g in self.gpos:
                for e, s in zip(self.settings[g.guid], g.settings):
                    if e["rule_id"] == r.id:
                        configured.append({"guid": g.guid, "name": g.name, "value": s.display, "status": e["status"], "effective": e["effective"],
                                           "linked_at_root": self.linked_at_root(g)})
            row = {"rule_id": r.id, "title": r.title, "category": r.category, "expected": r.expected, "risk": r.risk, "explanation": r.why,
                   "recommendation": r.fix, "reference": r.ref, "gpos": configured, "effective_values": [], "not_configured_in": []}
            if r.id in self.excluded:
                row.update(status="not_applicable", note=f"Excluded by an administrator: {self.excluded[r.id]}", recommendation="")
                out.append(row)
                continue
            paths = [self.root] if r.applies == "domain_account" else list(precedence)
            evals = []
            for p in paths:
                win = None
                for guid in precedence.get(p, []):
                    for k, s in maps[guid].items():
                        if kb.rule_for(s) is r and (r.applies != "domain_account" or self.linked_at_root(self.by_guid[guid])):
                            win = (guid, s)
                            break
                    if win:
                        break
                if not win:
                    row["not_configured_in"].append(self.display_path(p))
                    continue
                try:
                    ok = r.check(win[1].value)
                except Exception:  # noqa: BLE001
                    ok = None
                evals.append(ok)
                row["effective_values"].append({"ou": self.display_path(p), "gpo": self.by_guid[win[0]].name, "value": win[1].display,
                                                "status": "unknown" if ok is None else "compliant" if ok else "non_compliant"})
            if not evals:
                row.update(status="not_configured", risk="informational",
                           note="No linked, enabled GPO configures this setting. It may be set locally, by the OS default, or by another tool; "
                                "this is not automatically insecure but cannot be verified from Group Policy.")
            elif any(e is False for e in evals):
                row.update(status="non_compliant", note="")
            elif any(e is None for e in evals):
                row.update(status="unknown", risk="informational", note="The configured value could not be interpreted.")
            else:
                row.update(status="compliant", risk="informational", recommendation="",
                           note=("Not configured for: " + ", ".join(row["not_configured_in"][:10])) if row["not_configured_in"] and r.applies != "domain_account" else "")
            out.append(row)
        return out

    # ------------------------------------------------------------ summary
    def summary(self, baseline: list[dict] | None = None, overlaps: dict | None = None) -> dict:
        inv = self.inventory()
        baseline = baseline if baseline is not None else self.baseline()
        counts = {s: sum(1 for b in baseline if b["status"] == s) for s in kb.STATUSES}
        assessed = counts["compliant"] + counts["non_compliant"]
        by_risk = {r: sum(1 for b in baseline if b["status"] == "non_compliant" and b["risk"] == r) for r in kb.RISKS}
        ov = overlaps or self.overlaps()
        return {"domain": self.domain, "gpo_count": len(self.gpos), "enabled": sum(1 for g in self.gpos if g.computer_enabled and g.user_enabled),
                "partially_disabled": sum(1 for g in self.gpos if g.computer_enabled != g.user_enabled),
                "disabled": sum(1 for g in self.gpos if not g.computer_enabled and not g.user_enabled),
                "unlinked": sum(1 for r in inv if "Unlinked" in r["flags"]), "empty": sum(1 for r in inv if "Empty (no settings)" in r["flags"]),
                "orphaned": sum(1 for r in inv if any(f.startswith("Orphaned") for f in r["flags"])),
                "unused": sum(1 for r in inv if r["unused"]), "settings": sum(len(g.settings) for g in self.gpos),
                "baseline_counts": counts, "baseline_score": round(100 * counts["compliant"] / assessed) if assessed else None,
                "non_compliant_by_risk": by_risk, "conflicts": len(ov["conflicts"]), "duplicates": len(ov["duplicates"]),
                "ou_differences": len(ov["ou_differences"]), "exact_precedence": self.exact_precedence}

    def executive_summary(self, s: dict) -> str:
        parts = [f"The domain {self.domain or '(unknown)'} has {s['gpo_count']} Group Policy Objects containing {s['settings']} configured settings."]
        if s["baseline_score"] is not None:
            parts.append(f"Of the baseline settings that are configured, {s['baseline_counts']['compliant']} meet the security baseline and "
                         f"{s['baseline_counts']['non_compliant']} do not (score {s['baseline_score']}%).")
        hi = s["non_compliant_by_risk"]["critical"] + s["non_compliant_by_risk"]["high"]
        if hi:
            parts.append(f"{hi} non-compliant item(s) are rated critical or high risk and should be remediated first.")
        if s["baseline_counts"]["not_configured"]:
            parts.append(f"{s['baseline_counts']['not_configured']} baseline settings are not set by any GPO; they may be configured locally "
                         "or by other tools and need separate verification - they are not automatically insecure.")
        hygiene = [f"{s[k]} {label}" for k, label in (("unlinked", "unlinked"), ("empty", "empty"), ("disabled", "fully disabled"),
                                                       ("orphaned", "orphaned")) if s[k]]
        if hygiene:
            parts.append("Housekeeping: " + ", ".join(hygiene) + " GPO(s).")
        if s["conflicts"]:
            parts.append(f"{s['conflicts']} setting(s) are configured with conflicting values by GPOs applying to the same OU.")
        if not s["exact_precedence"]:
            parts.append("Precedence was derived from the links in the report (link order and block inheritance were not available).")
        return " ".join(parts)


# ------------------------------------------------------------------ comparisons
def compare(gpos: list[Gpo]) -> dict:
    """Side-by-side comparison of two or more GPOs, keyed by setting."""
    rows: dict[str, dict] = {}
    for idx, g in enumerate(gpos):
        for s in g.settings:
            k = f"{s.scope}|{s.key}"
            r = kb.rule_for(s)
            row = rows.setdefault(k, {"setting_key": s.key, "scope": s.scope, "name": r.title if r else s.name, "category": kb.category(s),
                                      "expected": r.expected if r else "", "values": [None] * len(gpos), "_raw": [None] * len(gpos)})
            row["values"][idx] = s.display
            row["_raw"][idx] = _vkey(s.value)
    out = []
    for row in rows.values():
        raw = row.pop("_raw")
        present = [v for v in raw if v is not None]
        row["state"] = "only_in_some" if len(present) < len(raw) else ("same" if len(set(present)) == 1 else "different")
        out.append(row)
    order = {"different": 0, "only_in_some": 1, "same": 2}
    meta = [{"guid": g.guid, "name": g.name, "status": g.status, "modified": g.modified, "links": [l.som_path for l in g.links]} for g in gpos]
    out.sort(key=lambda r: (order[r["state"]], r["category"], r["name"]))
    return {"gpos": meta, "rows": out, "counts": {k: sum(1 for r in out if r["state"] == k) for k in order}}


def diff_versions(old: Gpo | None, new: Gpo | None) -> dict:
    """Before/after comparison of two versions of the same GPO (setting level plus links/status)."""
    a = {f"{s.scope}|{s.key}": s for s in (old.settings if old else [])}
    b = {f"{s.scope}|{s.key}": s for s in (new.settings if new else [])}
    changes = []
    for k in sorted(set(a) | set(b)):
        sa, sb = a.get(k), b.get(k)
        s = sb or sa
        r = kb.rule_for(s)
        name = r.title if r else s.name
        if sa and not sb:
            changes.append({"change": "removed", "scope": s.scope, "name": name, "category": kb.category(s), "before": sa.display, "after": None})
        elif sb and not sa:
            changes.append({"change": "added", "scope": s.scope, "name": name, "category": kb.category(s), "before": None, "after": sb.display})
        elif _vkey(sa.value) != _vkey(sb.value):
            changes.append({"change": "modified", "scope": s.scope, "name": name, "category": kb.category(s), "before": sa.display, "after": sb.display})
    meta = []
    if old and new:
        if old.name != new.name:
            meta.append({"field": "Name", "before": old.name, "after": new.name})
        if old.status != new.status:
            meta.append({"field": "Status", "before": old.status, "after": new.status})
        la = sorted(f"{l.som_path}{' (enforced)' if l.enforced else ''}{'' if l.enabled else ' (disabled)'}" for l in old.links)
        lb = sorted(f"{l.som_path}{' (enforced)' if l.enforced else ''}{'' if l.enabled else ' (disabled)'}" for l in new.links)
        if la != lb:
            meta.append({"field": "Links", "before": ", ".join(la) or "none", "after": ", ".join(lb) or "none"})
        if old.wmi_filter != new.wmi_filter:
            meta.append({"field": "WMI filter", "before": old.wmi_filter or "none", "after": new.wmi_filter or "none"})
        if old.security_filtering != new.security_filtering:
            meta.append({"field": "Security filtering", "before": ", ".join(old.security_filtering), "after": ", ".join(new.security_filtering)})
    return {"settings": changes, "metadata": meta,
            "counts": {c: sum(1 for x in changes if x["change"] == c) for c in ("added", "removed", "modified")}}
