"""
Investigation Export Service
============================
Implements FR-12.2 (publication-quality PDF/HTML reports) and FR-12.3
(structured machine-readable ZIP export).

PDF generation prefers WeasyPrint when its native rendering libraries are
available, and gracefully falls back to ReportLab (pure-Python, no system
dependencies) otherwise so the report is always downloadable.

The machine-readable ZIP export (FR-12.3) contains:
  * events.csv        - canonical normalized events (with raw_ref columns)
  * findings.csv      - detection findings
  * iocs.csv          - indicators of compromise (users, IPs, files, hosts)
  * blast_radius.json - compromised / at-risk asset manifest
  * attack_path.json  - the traced attack-path graph nodes/edges
"""

import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.services.report_generator import generate_report_html

# --- PDF backend -----------------------------------------------------------
def _weasyprint_available() -> bool:
    try:
        from weasyprint import HTML  # noqa: F401
        return True
    except Exception:
        return False


def generate_pdf_report(
    investigation: Dict,
    findings: List[Dict],
    timeline: List[Dict],
    blast_radius: Dict,
    story: Dict,
    graph: Dict,
    evidence_files: List[Dict],
    confidence: Dict,
    entry_point: Optional[Dict],
) -> bytes:
    """Render a PDF report, preferring WeasyPrint then falling back to ReportLab."""
    if _weasyprint_available():
        try:
            from weasyprint import HTML
            html = generate_report_html(
                investigation, findings, timeline, blast_radius, story,
                graph, evidence_files, confidence, entry_point,
            )
            return HTML(string=html).write_pdf()
        except Exception:
            pass
    return _render_pdf_reportlab(
        investigation, findings, timeline, blast_radius, story,
        graph, evidence_files, confidence, entry_point,
    )


def _render_pdf_reportlab(
    investigation: Dict,
    findings: List[Dict],
    timeline: List[Dict],
    blast_radius: Dict,
    story: Dict,
    graph: Dict,
    evidence_files: List[Dict],
    confidence: Dict,
    entry_point: Optional[Dict],
) -> bytes:
    """Pure-Python PDF report via ReportLab (no system dependencies)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph, Spacer, SimpleDocTemplate, Table, TableStyle, ListFlowable, ListItem,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], fontSize=18, spaceAfter=8)
    h2 = ParagraphStyle("H2X", parent=styles["Heading2"], fontSize=13, spaceBefore=12, spaceAfter=6)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9)

    inv_name = investigation.get("name", "Investigation")
    inv_id = investigation.get("id", "-")
    risk = investigation.get("risk_level", "UNKNOWN")
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    story_elements = [
        Paragraph("DIGITAL FORENSICS INVESTIGATION REPORT", title_style),
        Paragraph(f"Investigation ID: <b>{inv_id}</b> &nbsp;|&nbsp; Name: <b>{inv_name}</b>", body),
        Paragraph(f"Generated: {now} &nbsp;|&nbsp; Risk Level: <b>{risk}</b>", body),
        Paragraph(f"Overall Confidence: <b>{confidence.get('score', 0):.1f}%</b> ({confidence.get('level', 'LOW')})", body),
        Spacer(1, 0.1 * inch),
    ]

    # Evidence integrity
    story_elements.append(Paragraph("Evidence Integrity", h2))
    if evidence_files:
        data = [["File", "Category", "Events", "SHA-256"]]
        for ef in evidence_files:
            data.append([ef.get("filename", ""), ef.get("category", ""),
                         f"{ef.get('event_count', 0)}", ef.get("sha256_hash", "-")])
        t = Table(data, colWidths=[2.2 * inch, 1.0 * inch, 0.7 * inch, 3.0 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#334155")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ]))
        story_elements.append(t)
    else:
        story_elements.append(Paragraph("No evidence files.", small))

    # Entry point
    story_elements.append(Paragraph("Initial Entry Point", h2))
    if entry_point:
        story_elements.append(Paragraph(
            f"Likely initial entry point: {entry_point.get('description', '')} "
            f"(event {entry_point.get('event_id', '')}, user '{entry_point.get('user', '')}', "
            f"from {entry_point.get('source_ip') or 'unknown'}, {entry_point.get('timestamp') or 'unknown'}). "
            f"Confidence: {entry_point.get('confidence', 0):.0f}%.", body))
    else:
        story_elements.append(Paragraph("Not identified.", body))

    # Blast radius
    story_elements.append(Paragraph("Blast Radius", h2))
    data = [
        ["Category", "Compromised", "At-Risk"],
        ["Users", ", ".join(blast_radius.get("compromised", {}).get("users", []) or blast_radius.get("users", [])) or "None",
         ", ".join(blast_radius.get("at_risk", {}).get("users", [])) or "None"],
        ["Hosts", ", ".join(blast_radius.get("compromised", {}).get("hosts", []) or blast_radius.get("hosts", [])) or "None",
         ", ".join(blast_radius.get("at_risk", {}).get("hosts", [])) or "None"],
        ["Files", ", ".join(blast_radius.get("compromised", {}).get("files", []) or blast_radius.get("files", [])) or "None", "-"],
    ]
    t = Table(data, colWidths=[1.0 * inch, 2.9 * inch, 2.9 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#334155")),
    ]))
    story_elements.append(t)

    # Findings
    story_elements.append(Paragraph("Findings", h2))
    if findings:
        for f in findings:
            reason = ParagraphStyle("r", parent=body, fontSize=9, textColor=colors.HexColor("#92400e"))
            story_elements.append(Paragraph(
                f"<b>{f.get('title', '')}</b> - {f.get('severity', 'INFO')} "
                f"(confidence {f.get('confidence', 0):.0f}%)", body))
            story_elements.append(Paragraph(f.get("description", ""), body))
            story_elements.append(Paragraph(f"Why: {f.get('reason', '')}", reason))
            story_elements.append(Spacer(1, 0.06 * inch))
    else:
        story_elements.append(Paragraph("No findings.", body))

    # Attack story
    story_elements.append(Paragraph("Attack Story", h2))
    story_elements.append(Paragraph(str(story.get("narrative", "No story generated.")).replace("\n", "<br/>"), body))

    # Limitations
    story_elements.append(Paragraph("Limitations", h2))
    limitations = story.get("limitations", [])
    if limitations:
        story_elements.append(ListFlowable(
            [ListItem(Paragraph(li, body), leftIndent=18) for li in limitations],
            bulletType="bullet",
        ))

    doc.build(story_elements)
    return buf.getvalue()


# --- Machine-readable ZIP export (FR-12.3) ---------------------------------
def _event_csv_rows(events: List[Dict]) -> List[Dict]:
    rows = []
    for ev in events:
        raw_ref = ev.get("raw_ref") or {}
        if isinstance(raw_ref, str):
            try:
                raw_ref = json.loads(raw_ref)
            except (ValueError, TypeError):
                raw_ref = {}
        rows.append({
            "event_id": ev.get("event_id"),
            "timestamp": ev.get("timestamp"),
            "event_type": ev.get("event_type"),
            "user": ev.get("user") or "",
            "source_ip": ev.get("source_ip") or "",
            "destination_ip": ev.get("destination_ip") or "",
            "source_host": ev.get("source_host") or "",
            "destination_host": ev.get("destination_host") or "",
            "file_path": ev.get("file_path") or "",
            "action": ev.get("action"),
            "status": ev.get("status") or "",
            "severity": ev.get("severity") or "INFO",
            "source_file": ev.get("source") or "",
            "raw_ref_file_hash": (raw_ref or {}).get("file_hash", ""),
            "raw_ref_line_index": (raw_ref or {}).get("line_index", ""),
        })
    return rows


def _ioc_rows(blast_radius: Dict, findings: List[Dict]) -> List[Dict]:
    iocs = []
    comp = blast_radius.get("compromised", {})
    for u in comp.get("users", []):
        iocs.append({"type": "user", "value": u, "status": "COMPROMISED", "finding": ""})
    for ip in comp.get("ips", []):
        iocs.append({"type": "ip", "value": ip, "status": "COMPROMISED", "finding": ""})
    for h in comp.get("hosts", []):
        iocs.append({"type": "host", "value": h, "status": "COMPROMISED", "finding": ""})
    for f in comp.get("files", []):
        iocs.append({"type": "file", "value": f, "status": "COMPROMISED", "finding": ""})
    for a in blast_radius.get("at_risk", {}).get("assets", []):
        iocs.append({"type": a.get("type", "asset"), "value": a.get("label", ""), "status": "AT_RISK", "finding": ""})
    for f in findings:
        for eid in f.get("related_event_ids", [])[:20]:
            iocs.append({"type": "event", "value": eid, "status": f.get("severity", "INFO"),
                         "finding": f.get("finding_id", "")})
    return iocs


def generate_export_zip(
    investigation: Dict,
    events: List[Dict],
    blast_radius: Dict,
    findings: List[Dict],
    attack_path: Dict,
    include_pdf: bool = True,
) -> bytes:
    """Build a ZIP archive of the machine-readable investigation export (FR-12.3)."""
    from datetime import datetime as _dt
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # events.csv
        event_rows = _event_csv_rows(events)
        if event_rows:
            fields = list(event_rows[0].keys())
            csv_buf = io.StringIO()
            writer = csv.DictWriter(csv_buf, fieldnames=fields)
            writer.writeheader()
            writer.writerows(event_rows)
            zf.writestr("events.csv", csv_buf.getvalue())

        # blast_radius.json
        zf.writestr("blast_radius.json", json.dumps(blast_radius, indent=2))

        # attack_path.json
        zf.writestr("attack_path.json", json.dumps(attack_path, indent=2))

        # findings.json
        zf.writestr("findings.json", json.dumps(findings, indent=2))

        # iocs.csv
        iocs = _ioc_rows(blast_radius, findings)
        if iocs:
            fields = list(iocs[0].keys())
            csv_buf = io.StringIO()
            writer = csv.DictWriter(csv_buf, fieldnames=fields)
            writer.writeheader()
            writer.writerows(iocs)
            zf.writestr("iocs.csv", csv_buf.getvalue())

        # publication-quality PDF report (FR-12.2)
        if include_pdf:
            try:
                pdf = generate_pdf_report(
                    investigation,
                    findings,
                    [],  # timeline included via report assembler when available
                    blast_radius,
                    {"narrative": "See report sections.", "limitations": []},
                    attack_path,
                    investigation.get("evidence_files", []),
                    investigation.get("confidence", {"score": 0, "level": "LOW"}) or {"score": 0, "level": "LOW"},
                    investigation.get("entry_point"),
                )
                zf.writestr("incident_report.pdf", pdf)
            except Exception:
                pass

    return buf.getvalue()
