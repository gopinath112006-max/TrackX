"""
Report Generator
================
Produces a print-friendly HTML investigation report from analysis results.
The report is self-contained and can be saved/printed/downloaded by the
investigator without needing an internet connection.
"""

from datetime import datetime
from html import escape
from typing import Dict, List

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#f59e0b",
    "MEDIUM": "#2563eb",
    "LOW": "#64748b",
    "INFO": "#94a3b8",
}


def _esc(value) -> str:
    """None-safe HTML escaping."""
    if value is None:
        return ""
    return escape(str(value))


def _sev_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev.upper(), "#64748b")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600">{escape(sev)}</span>'


def generate_report_html(
    investigation: Dict,
    findings: List[Dict],
    timeline: List[Dict],
    blast_radius: Dict,
    story: Dict,
    graph: Dict,
    evidence_files: List[Dict],
    confidence: Dict,
    entry_point: Dict | None,
) -> str:
    """
    Build a complete HTML string for the print-friendly report.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    inv_name = escape(investigation.get("name", "Investigation"))
    inv_id = investigation.get("id", "-")
    risk = escape(investigation.get("risk_level", "UNKNOWN"))

    # Findings section
    findings_html = ""
    if findings:
        for f in findings:
            reasons_html = escape(f.get("reason", ""))
            ev_list = "".join(
                f'<code style="background:#0f172a;color:#60a5fa;padding:1px 6px;border-radius:3px;font-size:11px;margin-right:4px">{escape(e)}</code>'
                for e in f.get("related_event_ids", [])[:8]
            )
            findings_html += f"""
            <div style="border:1px solid #334155;background:#1e293b;border-radius:8px;padding:12px 16px;margin-bottom:12px;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <strong style="color:#f8fafc;font-size:14px;">{escape(f.get('title', ''))}</strong>
                {_sev_badge(f.get('severity', 'INFO'))}
              </div>
              <div style="color:#94a3b8;font-size:13px;margin-bottom:8px;">Confidence: {f.get('confidence', 0):.0f}%</div>
              <p style="color:#cbd5e1;font-size:13px;margin:0 0 8px;">{escape(f.get('description', ''))}</p>
              <p style="color:#fbbf24;font-size:12px;margin:0 0 6px;">Why: {reasons_html}</p>
              <div>Evidence: {ev_list}</div>
            </div>
            """

    # Timeline section
    timeline_html = ""
    if timeline:
        rows = []
        for t in timeline:
            sev = t.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev.upper(), "#94a3b8")
            rows.append(
                f"<tr style='border-bottom:1px solid #1e293b'>"
                f"<td style='padding:6px 8px;color:#94a3b8;width:90px;white-space:nowrap;'>{escape(t.get('timestamp', ''))}</td>"
                f"<td style='padding:6px 8px;color:#e2e8f0'>{escape(t.get('display_text', ''))}</td>"
                f"<td style='padding:6px 8px;'>{_sev_badge(sev)}</td>"
                f"</tr>"
            )
        timeline_html = (
            "<table style='width:100%;border-collapse:collapse;font-size:12px;'>"
            + "".join(rows)
            + "</table>"
        )

    # Blast radius section
    br_users = ", ".join(blast_radius.get("users", [])) or "None"
    br_ips = ", ".join(blast_radius.get("ips", [])) or "None"
    br_hosts = ", ".join(blast_radius.get("hosts", [])) or "None"
    br_files = ", ".join(blast_radius.get("files", [])) or "None"

    # Story section
    story_html = escape(story.get("narrative", "No story generated.")).replace("\n", "<br/>")
    limitations_html = "".join(f"<li style='margin-bottom:4px;'>{escape(l)}</li>" for l in story.get("limitations", []))

    confidence_html = escape(", ".join(confidence.get("factors", [])))

    # Entry point
    ep_html = "Not identified"
    if entry_point:
        ep_html = (
            f"Likely initial entry point: {_esc(entry_point.get('description'))} "
            f"(event {_esc(entry_point.get('event_id'))}, "
            f"user '{_esc(entry_point.get('user'))}', "
            f"from {_esc(entry_point.get('source_ip') or 'unknown')}, "
            f"{_esc(entry_point.get('timestamp') or 'unknown')}). "
            f"Confidence: {entry_point.get('confidence', 0):.0f}%"
        )

    # Evidence files
    ef_html = ""
    if evidence_files:
        rows = []
        for ef in evidence_files:
            rows.append(
                f"<tr style='border-bottom:1px solid #1e293b'>"
                f"<td style='padding:6px 8px;color:#e2e8f0'>{escape(ef.get('filename', ''))}</td>"
                f"<td style='padding:6px 8px;color:#94a3b8'>{escape(ef.get('category', ''))}</td>"
                f"<td style='padding:6px 8px;color:#94a3b8'>{ef.get('event_count', 0)}</td>"
                f"<td style='padding:6px 8px;font-family:monospace;color:#94a3b8;font-size:11px'>{escape(ef.get('sha256_hash', '-'))}</td>"
                f"</tr>"
            )
        ef_html = (
            "<table style='width:100%;border-collapse:collapse;font-size:12px;'>"
            + "".join(rows)
            + "</table>"
        )
    else:
        ef_html = "<p style='color:#64748b;font-size:13px;'>No evidence files</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Forensic Investigation Report - {inv_name}</title>
<style>
  body {{ background: #0f172a; color: #e2e8f0; font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 24px; }}
  h1 {{ color: #f8fafc; font-size: 22px; margin: 0 0 4px; }}
  h2 {{ color: #60a5fa; font-size: 16px; margin: 24px 0 10px; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
  .meta {{ color: #94a3b8; font-size: 13px; margin-bottom: 6px; }}
  .box {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; }}
  .risk {{ font-weight: 700; font-size: 18px; }}
  @media print {{
    body {{ background: #fff; color: #111; }}
    .box {{ background: #f8fafc; border-color: #ccc; }}
    h2 {{ color: #1e40af; }}
    tr {{ page-break-inside: avoid; }}
  }}
</style>
</head>
<body>
  <h1>DIGITAL FORENSICS INVESTIGATION REPORT</h1>
  <div class="meta">Investigation ID: <strong>{inv_id}</strong></div>
  <div class="meta">Investigation: <strong>{inv_name}</strong></div>
  <div class="meta">Generated: {now}</div>
  <div class="meta">Risk Level: <span class="risk" style="color:{SEVERITY_COLORS.get(risk.upper(), '#f59e0b')}">{escape(risk)}</span></div>
  <div class="meta">Overall Confidence: <strong>{confidence.get('score', 0):.1f}%</strong></div>

  <h2>Evidence Integrity</h2>
  <div class="box">{ef_html}</div>

  <h2>Initial Entry Point</h2>
  <div class="box"><p style="margin:0;font-size:14px;">{ep_html}</p></div>

  <h2>Blast Radius</h2>
  <div class="box">
    <p style="margin:0 0 6px;"><strong>Affected Users:</strong> {escape(br_users)}</p>
    <p style="margin:0 0 6px;"><strong>Affected IPs:</strong> {escape(br_ips)}</p>
    <p style="margin:0 0 6px;"><strong>Affected Hosts:</strong> {escape(br_hosts)}</p>
    <p style="margin:0 0 6px;"><strong>Affected Files:</strong> {escape(br_files)}</p>
    <p style="margin:0;"><strong>Total affected entities:</strong> {blast_radius.get('total_affected', 0)}</p>
  </div>

  <h2>Attack Timeline</h2>
  <div class="box">{timeline_html}</div>

  <h2>Findings</h2>
  <div class="box">{findings_html}</div>

  <h2>Attack Story</h2>
  <div class="box"><p style="font-size:14px;line-height:1.6;">{story_html}</p></div>

  <h2>Confidence Breakdown</h2>
  <div class="box">
    <p style="margin:0 0 6px;"><strong>Overall Confidence:</strong> {confidence.get('score', 0):.1f}% ({confidence.get('level', 'LOW')})</p>
    <p style="margin:0;color:#94a3b8;font-size:13px;">Reasons: {confidence_html or 'No factors listed.'}</p>
  </div>

  <h2>Limitations</h2>
  <div class="box"><ul style="margin:0;padding-left:18px;font-size:13px;color:#cbd5e1;">{limitations_html}</ul></div>

</body>
</html>"""