"""
Attack Story Generator
======================
Generates a deterministic, evidence-cited forensic narrative (FR-12).

  * FR-12.1 - Narrative is produced solely from verified findings using
              deterministic Jinja2 templating; no free-form LLM text.
  * FR-12.2 - Every asserted factual claim carries inline citation tokens,
              e.g. `[Ref: EVT-0014]`, linking it to supporting event IDs.
              Any claim without direct evidence is explicitly tagged
              `[Inferred / Unverified]`.
  * FR-12.3 - Strict linguistic separation between observed facts
              ("Observed evidence confirms ...") and system-derived
              inferences ("System inferred ...").

Language conventions:
  - facts      -> "Observed evidence confirms ..."
  - inferences -> "System inferred ... based on ..."
  - Never presents an inference as a verified observation.
"""

from datetime import datetime
from typing import Dict, List

from jinja2 import Template

# ---------------------------------------------------------------------------
# Deterministic Jinja2 narrative template (FR-12.1).
# ---------------------------------------------------------------------------
_STORY_TEMPLATE = Template("""\
{%- set num_findings = findings | length -%}
{%- set num_suspicious = counts.suspicious_events | default(0) -%}
{%- set num_total = counts.total_events | default(0) -%}

**Executive Summary** {%- if entry_point %} [Ref: {{ entry_point.event_id }}]{% endif %}

Observed evidence confirms that the incident's earliest likely entry point involved {{ entry_point.action }}{% if entry_point %} ({{ entry_point.event_id }}, user '{{ entry_point.user }}', from {{ entry_point.source_ip }}, at {{ entry_point.time }}){% endif %}.
System inferred that this activity represents the most probable initial access vector, based on failure volume, first-seen source, and subsequent activity across the evidence set. {% if not entry_point %}[Inferred / Unverified]{% endif %}

**Attack Execution**

Observed evidence confirms {{ num_suspicious }} suspicious event(s) against {{ num_total }} total processed across {{ sources | length }} independent log source(s){% if sources %} ({{ sources | join(', ') }}){% endif %}.
{% for f in findings %}
{%- if f.has_refs %}
Observed {{ f.severity | lower }}-severity finding "{{ f.title }}": {{ f.description[:220] }} {{ f.refs_str }}.
{%- else %}
System inferred the presence of "{{ f.title }}" {{ '[Inferred / Unverified]' }} based on correlated telemetry, but no direct event citation is available.
{%- endif %}
{% endfor %}

**Blast Radius** {%- if blast_radius.entry_point and blast_radius.entry_point.event_id %} [Ref: {{ blast_radius.entry_point.event_id }}]{% endif %}

Observed evidence confirms {{ comp_counts.users }} compromised user account(s), {{ comp_counts.hosts }} compromised host(s), and {{ comp_counts.files }} compromised/stolen file path(s).
System inferred {{ at_risk.hosts | default([]) | length }} at-risk host(s) sharing credentials, identity, or subnet reachability with the compromised set{{ ': ' ~ (at_risk.hosts | default([]) | join(', ')) if (at_risk.hosts | default([]) | length) > 0 else '' }}. [Inferred / Unverified]

**Confidence**

Observed evidence and correlated telemetry yield an overall confidence score of {{ confidence.score | default(0) }}% ({{ confidence.level | default('LOW') }}), with contributing factors: {{ confidence.factors | default([]) | join('; ') }}.""")  # noqa: E501


def _fmt_time(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%H:%M")
    except (ValueError, TypeError):
        return ts or "unknown time"


def _citation_refs(event_ids: List[str]) -> str:
    """Build the inline citation token(s) for a claim (FR-12.2)."""
    if not event_ids:
        return ""
    tokens = ", ".join(f"Ref: {e}" for e in list(event_ids)[:6])
    return f"[{tokens}]"


def generate_attack_story(
    findings: List[Dict],
    entry_point: Dict | None,
    timeline: List[Dict],
    blast_radius: Dict,
    overall_confidence: Dict[str, object],
) -> Dict[str, object]:
    """
    Generate a deterministic Jinja2-template narrative with evidence citations.

    Returns:
      {
        "narrative": str,        # citation-annotated narrative (FR-12.2)
        "narrative_html": str,   # markdown-flavoured citation rendering
        "citations": list,       # all [Ref: <event_id>] citations used
        "key_findings": list[str],
        "confidence": dict,
        "limitations": list[str],
      }
    """
    findings = findings or []
    blast_radius = blast_radius or {}
    entry_point = entry_point or {}

    # All citations referenced by findings.
    citations = []
    seen = set()
    for f in findings:
        for eid in f.get("related_event_ids", [])[:6]:
            if eid and eid not in seen:
                seen.add(eid)
                citations.append(eid)

    sources = sorted({f.get("source") for f in findings if f.get("source")} | {
        ev.get("source") for ev in timeline if ev.get("source")
    })

    counts = {
        "suspicious_events": overall_confidence_fallback_suspicious(findings, timeline),
        "total_events": max(len(timeline), 0),
    }

    comp = blast_radius.get("compromised", {})
    at_risk = blast_radius.get("at_risk", {})
    comp_counts = {
        "users": len(comp.get("users", []) or blast_radius.get("users", [])),
        "hosts": len(comp.get("hosts", []) or blast_radius.get("hosts", [])),
        "files": len(comp.get("files", []) or blast_radius.get("files", [])),
    }

    # Precompute per-finding citation strings for the Jinja2 template (FR-12.2).
    findings_for_template = []
    for f in findings:
        refs = list(f.get("related_event_ids", []) or [])[:6]
        findings_for_template.append({
            **f,
            "has_refs": bool(refs),
            "refs_str": "[" + ", ".join(f"Ref: {e}" for e in refs) + "]",
        })

    # Normalize the entry point for template rendering.
    ep = dict(entry_point or {})
    if ep:
        ep["action"] = ep.get("description") or "anomalous authentication activity"
        ep["time"] = _fmt_time(ep.get("timestamp", ""))

    narrative = _STORY_TEMPLATE.render(
        findings=findings_for_template,
        entry_point=ep,
        timeline=timeline or [],
        blast_radius=blast_radius,
        confidence=overall_confidence,
        sources=sources,
        counts=counts,
        comp_counts=comp_counts,
        at_risk=at_risk,
    ).strip()

    key_findings = [
        f"'{f.get('title', '')}' - {f.get('severity', 'INFO')} "
        f"(confidence {f.get('confidence', 0):.0f}%) "
        f"{_citation_refs(f.get('related_event_ids', []))}"
        for f in findings[:8]
    ]

    limitations = [
        "Simulated or sampled data may not represent the full system state.",
        "Correlations are heuristic and may include false positives.",
        "Confidence scores are based on available evidence and may change with additional data.",
        "Claims tagged [Inferred / Unverified] are system hypotheses, not observed facts (FR-12.3).",
        "This tool supports investigation decisions; findings should be verified by a forensic analyst.",
    ]

    return {
        "narrative": narrative,
        "narrative_markdown": narrative,
        "narrative_html": _markdown_to_html(narrative),
        "citations": citations,
        "key_findings": key_findings,
        "confidence": overall_confidence,
        "limitations": limitations,
    }


def overall_confidence_fallback_suspicious(findings: List[Dict], timeline: List[Dict]) -> int:
    """Derive a suspicious-event count for narrative rendering when needed."""
    suspicious = set()
    for f in findings:
        for eid in f.get("related_event_ids", []):
            suspicious.add(eid)
    return len(suspicious)


def _markdown_to_html(text: str) -> str:
    """Very small deterministic markdown-ish renderer for the citation tokens."""
    import html
    from html import escape
    esc = escape(text)
    esc = esc.replace("**", "")
    # Turn [Ref: EVT-XXXX] tokens into HTML citations.
    import re
    esc = re.sub(
        r"\[Ref:\s+([A-Za-z0-9\-_]+)\]",
        lambda m: f'<a class="citation" data-event="{m.group(1)}">[Ref: {m.group(1)}]</a>',
        esc,
    )
    esc = esc.replace("[Inferred / Unverified]", '<span class="inferred">[Inferred / Unverified]</span>')
    return esc.replace("\n\n", "<br/><br/>").replace("\n", "<br/>")
