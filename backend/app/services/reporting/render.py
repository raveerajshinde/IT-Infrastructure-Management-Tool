"""Report document model and renderers (HTML, PDF, Excel, CSV).

Every report in InfraPilot (Group Policy, IT audit, Active Directory, Report Center) is built once as a `Doc`
and rendered to any format, so the content of a PDF, the Excel workbook and the HTML page is always identical.
"""
from __future__ import annotations

import html
import io
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.timeutil import utcnow

TONES = {
    "critical": ("#7f1d1d", "#fee2e2"), "high": ("#9a3412", "#ffedd5"), "medium": ("#854d0e", "#fef9c3"), "low": ("#1e40af", "#dbeafe"),
    "informational": ("#334155", "#f1f5f9"), "compliant": ("#166534", "#dcfce7"), "non_compliant": ("#991b1b", "#fee2e2"),
    "non-compliant": ("#991b1b", "#fee2e2"), "partial": ("#854d0e", "#fef9c3"), "partially compliant": ("#854d0e", "#fef9c3"),
    "not_configured": ("#475569", "#f1f5f9"), "not configured": ("#475569", "#f1f5f9"), "not_applicable": ("#475569", "#f8fafc"),
    "not applicable": ("#475569", "#f8fafc"), "unknown": ("#6b21a8", "#f3e8ff"), "not assessed": ("#475569", "#f1f5f9"),
    "not_assessed": ("#475569", "#f1f5f9"), "open": ("#991b1b", "#fee2e2"), "closed": ("#166534", "#dcfce7"),
    "accepted risk": ("#6b21a8", "#f3e8ff"), "ok": ("#166534", "#dcfce7"), "missing": ("#991b1b", "#fee2e2"), "stale": ("#854d0e", "#fef9c3"),
}


@dataclass
class Table:
    columns: list[str]
    rows: list[list[Any]]
    title: str = ""
    tone_columns: tuple[str, ...] = ("Status", "Risk", "Severity", "Result")
    widths: list[float] | None = None     # relative column widths for PDF
    sheet: str = ""                       # Excel sheet name (defaults to title)


@dataclass
class Section:
    title: str
    paragraphs: list[str] = field(default_factory=list)
    kv: list[tuple[str, Any]] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    children: list["Section"] = field(default_factory=list)
    bullets: list[str] = field(default_factory=list)


@dataclass
class Doc:
    title: str
    subtitle: str = ""
    meta: list[tuple[str, Any]] = field(default_factory=list)
    kpis: list[tuple[str, Any, str]] = field(default_factory=list)   # (label, value, tone)
    sections: list[Section] = field(default_factory=list)
    organisation: str = ""
    classification: str = "Confidential - internal use"
    generated_at: datetime = field(default_factory=utcnow)
    sample: bool = False

    def all_tables(self) -> list[tuple[str, Table]]:
        out = []

        def walk(sec: Section, prefix: str):
            for t in sec.tables:
                out.append((t.sheet or t.title or sec.title, t))
            for c in sec.children:
                walk(c, prefix + sec.title + " / ")
        for s in self.sections:
            walk(s, "")
        return out


def _s(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, (list, tuple)):
        return ", ".join(_s(x) for x in v)
    return str(v)


def _tone(v: Any) -> tuple[str, str] | None:
    return TONES.get(_s(v).strip().lower().replace("_", " ")) or TONES.get(_s(v).strip().lower())


# ------------------------------------------------------------------ HTML
_CSS = """
:root{--b:#0f172a;--m:#475569;--l:#e2e8f0;--a:#1d4ed8}
*{box-sizing:border-box}body{font:13px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--b);margin:0;background:#f8fafc}
.page{max-width:1180px;margin:0 auto;padding:32px 40px;background:#fff}
header{border-bottom:3px solid var(--a);padding-bottom:14px;margin-bottom:20px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--l)}
h3{font-size:15px;margin:18px 0 6px}h4{font-size:13px;margin:14px 0 6px}
.sub{color:var(--m)}.meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:4px 18px;margin-top:10px;color:var(--m);font-size:12px}
.meta b{color:var(--b);font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:18px 0}
.kpi{border:1px solid var(--l);border-radius:8px;padding:10px 12px}.kpi .v{font-size:22px;font-weight:700}.kpi .l{color:var(--m);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;margin:8px 0 14px;font-size:12px}th{background:#1e293b;color:#fff;text-align:left;padding:6px 8px;font-weight:600;position:sticky;top:0}
td{border-bottom:1px solid var(--l);padding:5px 8px;vertical-align:top}tr:nth-child(even) td{background:#f8fafc}
.badge{display:inline-block;border-radius:999px;padding:1px 8px;font-size:11px;font-weight:600;white-space:nowrap}
.kv{display:grid;grid-template-columns:220px 1fr;gap:3px 12px;margin:6px 0 12px}.kv div:nth-child(odd){color:var(--m)}
.sample{background:#7c3aed;color:#fff;padding:6px 12px;border-radius:6px;font-weight:600;margin-bottom:12px}
footer{margin-top:30px;border-top:1px solid var(--l);padding-top:8px;color:var(--m);font-size:11px}
.toc a{color:var(--a);text-decoration:none}.toc ol{margin:4px 0 0 18px;padding:0}
@media print{body{background:#fff}.page{padding:0;max-width:none}th{position:static}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def to_html(doc: Doc) -> bytes:
    e = html.escape
    out = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>{e(doc.title)}</title><style>{_CSS}</style></head><body><div class='page'>"]
    if doc.sample:
        out.append("<div class='sample'>SAMPLE DATA - this report was generated from fictitious sample input, not from your environment.</div>")
    out.append(f"<header><h1>{e(doc.title)}</h1>")
    if doc.subtitle:
        out.append(f"<div class='sub'>{e(doc.subtitle)}</div>")
    meta = [*doc.meta, ("Generated", doc.generated_at.strftime("%Y-%m-%d %H:%M UTC"))]
    if doc.organisation:
        meta.insert(0, ("Organisation", doc.organisation))
    out.append("<div class='meta'>" + "".join(f"<div>{e(k)}: <b>{e(_s(v))}</b></div>" for k, v in meta) + "</div></header>")
    if doc.kpis:
        out.append("<div class='kpis'>")
        for label, v, tone in doc.kpis:
            fg = TONES.get(tone, ("#0f172a", "#fff"))[0]
            out.append(f"<div class='kpi'><div class='v' style='color:{fg}'>{e(_s(v))}</div><div class='l'>{e(label)}</div></div>")
        out.append("</div>")
    if len(doc.sections) > 3:
        out.append("<nav class='toc'><b>Contents</b><ol>" + "".join(f"<li><a href='#s{i}'>{e(s.title)}</a></li>" for i, s in enumerate(doc.sections, 1)) + "</ol></nav>")

    def table(t: Table):
        if t.title:
            out.append(f"<h4>{e(t.title)}</h4>")
        if not t.rows:
            out.append("<p class='sub'>None.</p>")
            return
        toned = {i for i, c in enumerate(t.columns) if c in t.tone_columns}
        out.append("<table><thead><tr>" + "".join(f"<th>{e(c)}</th>" for c in t.columns) + "</tr></thead><tbody>")
        for r in t.rows:
            cells = []
            for i, v in enumerate(r):
                tn = _tone(v) if i in toned else None
                cells.append(f"<td><span class='badge' style='color:{tn[0]};background:{tn[1]}'>{e(_s(v))}</span></td>" if tn and _s(v)
                             else f"<td>{e(_s(v))}</td>")
            out.append("<tr>" + "".join(cells) + "</tr>")
        out.append("</tbody></table>")

    def section(s: Section, level: int, anchor: str | None):
        tag = f"h{min(level + 1, 4)}"
        out.append(f"<{tag}{f' id={chr(39)}{anchor}{chr(39)}' if anchor else ''}>{e(s.title)}</{tag}>")
        for p in s.paragraphs:
            out.append(f"<p>{e(p)}</p>")
        if s.bullets:
            out.append("<ul>" + "".join(f"<li>{e(b)}</li>" for b in s.bullets) + "</ul>")
        if s.kv:
            out.append("<div class='kv'>" + "".join(f"<div>{e(k)}</div><div>{e(_s(v))}</div>" for k, v in s.kv) + "</div>")
        for t in s.tables:
            table(t)
        for c in s.children:
            section(c, level + 1, None)
    for i, s in enumerate(doc.sections, 1):
        section(s, 1, f"s{i}")
    out.append(f"<footer>{e(doc.classification)} · Generated by InfraPilot on {doc.generated_at.strftime('%Y-%m-%d %H:%M UTC')} · "
               "Findings reflect data available to InfraPilot at generation time; this report is not a certification.</footer></div></body></html>")
    return "".join(out).encode("utf-8")


# ------------------------------------------------------------------ PDF
def to_pdf(doc: Doc) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table as RLTable, TableStyle

    buf = io.BytesIO()
    page = landscape(A4)
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontName="Helvetica", fontSize=8.8, leading=11.5)
    cell = ParagraphStyle("c", parent=body, fontSize=7.6, leading=9.4, alignment=TA_LEFT)
    hcell = ParagraphStyle("hc", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24, alignment=TA_LEFT, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=13.5, leading=17, spaceBefore=10, spaceAfter=5,
                        textColor=colors.HexColor("#1d4ed8"))
    h3 = ParagraphStyle("h3", parent=ss["Heading3"], fontName="Helvetica-Bold", fontSize=10.5, leading=13, spaceBefore=7, spaceAfter=3)
    h4 = ParagraphStyle("h4", parent=h3, fontSize=9.2, leading=11.5)
    sub = ParagraphStyle("sub", parent=body, textColor=colors.HexColor("#475569"))
    e = html.escape

    def P(t, st=body):
        return Paragraph(e(_s(t)).replace("\n", "<br/>"), st)

    story: list = []
    if doc.sample:
        story.append(Table_banner := RLTable([[P("SAMPLE DATA - generated from fictitious sample input, not from your environment.", hcell)]],
                                             colWidths=[page[0] - 30 * mm]))
        Table_banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#7c3aed")), ("TOPPADDING", (0, 0), (-1, -1), 4)]))
        story.append(Spacer(1, 6))
    story.append(P(doc.title, h1))
    if doc.subtitle:
        story.append(P(doc.subtitle, sub))
    meta = [*([("Organisation", doc.organisation)] if doc.organisation else []), *doc.meta, ("Generated", doc.generated_at.strftime("%Y-%m-%d %H:%M UTC")),
            ("Classification", doc.classification)]
    mrows = [[P(f"{k}:", sub), P(_s(v))] for k, v in meta]
    mt = RLTable(mrows, colWidths=[45 * mm, page[0] - 30 * mm - 45 * mm])
    mt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 1), ("TOPPADDING", (0, 0), (-1, -1), 1)]))
    story += [Spacer(1, 6), mt, Spacer(1, 8)]
    if doc.kpis:
        per = 6
        rows = []
        for i in range(0, len(doc.kpis), per):
            chunk = doc.kpis[i:i + per]
            rows.append([Paragraph(f"<font size=15 color='{TONES.get(t, ('#0f172a',))[0]}'><b>{e(_s(v))}</b></font><br/>"
                                   f"<font size=7 color='#475569'>{e(l.upper())}</font>", body) for l, v, t in chunk] + [""] * (per - len(chunk)))
        kt = RLTable(rows, colWidths=[(page[0] - 30 * mm) / per] * per)
        kt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")), ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                                ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story += [kt, Spacer(1, 8)]
    avail = page[0] - 30 * mm

    def table(t: Table):
        if t.title:
            story.append(P(t.title, h4))
        if not t.rows:
            story.append(P("None.", sub))
            return
        n = len(t.columns)
        w = t.widths or [1] * n
        tot = sum(w)
        widths = [avail * x / tot for x in w]
        data = [[P(c, hcell) for c in t.columns]]
        toned = {i for i, c in enumerate(t.columns) if c in t.tone_columns}
        style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")), ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                 ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5), ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
        for ri, r in enumerate(t.rows[:5000], start=1):
            row = []
            for ci, v in enumerate(r):
                txt = _s(v)
                if len(txt) > 1500:
                    txt = txt[:1500] + " …"
                row.append(P(txt, cell))
                tn = _tone(v) if ci in toned else None
                if tn:
                    style += [("BACKGROUND", (ci, ri), (ci, ri), colors.HexColor(tn[1])), ("TEXTCOLOR", (ci, ri), (ci, ri), colors.HexColor(tn[0]))]
            if ri % 2 == 0:
                style.append(("BACKGROUND", (0, ri), (-1, ri), colors.HexColor("#f8fafc")))
                for ci in toned:  # keep tone colours on top of zebra striping
                    tn = _tone(r[ci]) if ci < len(r) else None
                    if tn:
                        style.append(("BACKGROUND", (ci, ri), (ci, ri), colors.HexColor(tn[1])))
            data.append(row)
        rt = RLTable(data, colWidths=widths, repeatRows=1)
        rt.setStyle(TableStyle(style))
        story.append(rt)
        if len(t.rows) > 5000:
            story.append(P(f"Showing the first 5,000 of {len(t.rows)} rows - see the Excel export for all rows.", sub))
        story.append(Spacer(1, 6))

    def section(s: Section, level: int):
        hd = [P(s.title, h2 if level == 1 else h3 if level == 2 else h4)]
        first = [P(p) for p in s.paragraphs[:1]]
        story.append(KeepTogether(hd + first))
        for p in s.paragraphs[1:]:
            story.append(P(p))
        for b in s.bullets:
            story.append(Paragraph("• " + e(b), body))
        if s.kv:
            kv = RLTable([[P(k, sub), P(_s(v))] for k, v in s.kv], colWidths=[60 * mm, avail - 60 * mm])
            kv.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1)]))
            story.append(kv)
        for t in s.tables:
            table(t)
        for c in s.children:
            section(c, level + 1)

    for i, s in enumerate(doc.sections):
        if i and s.tables and sum(len(t.rows) for t in s.tables) > 25:
            story.append(PageBreak())
        section(s, 1)

    def frame(canv, d):
        canv.saveState()
        canv.setFont("Helvetica", 7)
        canv.setFillColor(colors.HexColor("#64748b"))
        canv.drawString(15 * mm, 8 * mm, f"{doc.title[:90]} · {doc.classification}")
        canv.drawRightString(page[0] - 15 * mm, 8 * mm, f"Page {d.page} · InfraPilot · {doc.generated_at.strftime('%Y-%m-%d %H:%M UTC')}")
        canv.setStrokeColor(colors.HexColor("#1d4ed8"))
        canv.setLineWidth(1.2)
        canv.line(15 * mm, page[1] - 10 * mm, page[0] - 15 * mm, page[1] - 10 * mm)
        canv.restoreState()

    SimpleDocTemplate(buf, pagesize=page, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                      title=doc.title, author="InfraPilot", subject=doc.subtitle).build(story, onFirstPage=frame, onLaterPages=frame)
    return buf.getvalue()


# ------------------------------------------------------------------ Excel / CSV
def _safe(v: Any):
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
        return "'" + v
    if isinstance(v, (list, tuple, dict)):
        return _s(v)
    if isinstance(v, datetime):
        return v
    return v


def to_xlsx(doc: Doc) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    ws.append([doc.title])
    ws["A1"].font = Font(bold=True, size=14)
    if doc.sample:
        ws.append(["SAMPLE DATA - generated from fictitious sample input"])
    if doc.subtitle:
        ws.append([doc.subtitle])
    for k, v in [*doc.meta, ("Generated", doc.generated_at.strftime("%Y-%m-%d %H:%M UTC")), ("Classification", doc.classification)]:
        ws.append([k, _safe(_s(v))])
    if doc.kpis:
        ws.append([])
        for label, v, _t in doc.kpis:
            ws.append([label, _safe(v)])
    for s in doc.sections:
        if s.paragraphs or s.kv:
            ws.append([])
            ws.append([s.title])
            ws.cell(ws.max_row, 1).font = Font(bold=True)
            for p in s.paragraphs:
                ws.append([p])
            for k, v in s.kv:
                ws.append([k, _safe(_s(v))])
    ws.column_dimensions["A"].width = 38
    ws.column_dimensions["B"].width = 90
    used: set[str] = {"Summary"}
    for name, t in doc.all_tables():
        base = "".join(ch for ch in (name or "Data") if ch not in '[]:*?/\\')[:28] or "Data"
        nm, i = base, 2
        while nm in used:
            nm, i = f"{base[:25]} {i}", i + 1
        used.add(nm)
        sh = wb.create_sheet(nm)
        sh.append(t.columns)
        for c in sh[1]:
            c.font = Font(bold=True, color="FFFFFF")
            c.fill = PatternFill("solid", fgColor="1E293B")
        toned = {i for i, c in enumerate(t.columns) if c in t.tone_columns}
        for r in t.rows:
            sh.append([_safe(v) for v in r])
            for ci in toned:
                tn = _tone(r[ci]) if ci < len(r) else None
                if tn:
                    cl = sh.cell(sh.max_row, ci + 1)
                    cl.fill = PatternFill("solid", fgColor=tn[1].lstrip("#"))
                    cl.font = Font(color=tn[0].lstrip("#"), bold=True)
        sh.freeze_panes = "A2"
        sh.auto_filter.ref = sh.dimensions
        for ci, col in enumerate(sh.columns):
            width = max(len(_s(c.value)) for c in col) + 2
            sh.column_dimensions[col[0].column_letter].width = min(60, max(10, width))
            if width > 60:
                for c in col[1:]:
                    c.alignment = Alignment(wrap_text=True, vertical="top")
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def to_csv(doc: Doc) -> bytes:
    """CSV holds the tables one after another, each preceded by its title (spreadsheet-formula safe)."""
    import csv
    buf = io.StringIO()
    w = csv.writer(buf)
    tables = doc.all_tables()
    for i, (name, t) in enumerate(tables):
        if len(tables) > 1:
            if i:
                w.writerow([])
            w.writerow([f"# {name}"])
        w.writerow(t.columns)
        for r in t.rows:
            w.writerow([_safe(_s(v)) for v in r])
    return buf.getvalue().encode("utf-8-sig")


MEDIA = {"pdf": "application/pdf", "html": "text/html; charset=utf-8", "csv": "text/csv",
         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def render(doc: Doc, fmt: str) -> bytes:
    return {"pdf": to_pdf, "html": to_html, "xlsx": to_xlsx, "csv": to_csv}[fmt](doc)
