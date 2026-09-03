"""
Analysis Engine
===============
Orchestrates the full investigation pipeline:
  events -> correlation -> detection -> entry point -> blast radius
          -> timeline -> graph -> confidence -> story
"""

from typing import Callable, Dict, List, Optional

from app.analysis.blast_radius import calculate_blast_radius
from app.analysis.confidence_scorer import (
    risk_level_for,
    score_investigation_confidence,
)
from app.analysis.correlation_engine import correlate_events
from app.analysis.entry_point_detector import find_initial_entry_point
from app.analysis.relationship_builder import build_relationship_graph
from app.analysis.story_generator import generate_attack_story
from app.analysis.suspicious_detector import detect_suspicious_activities
from app.analysis.timeline_builder import build_timeline
from app.schemas.schemas import NormalizedEvent


def run_analysis(
    events: List[NormalizedEvent],
    relationships_from_db: List[Dict] | None = None,
    on_stage: Optional[Callable[[str, Dict], None]] = None,
) -> Dict[str, object]:
    """
    Run the complete analysis pipeline on a set of normalized events.

    Args:
        events: normalized events to analyze.
        relationships_from_db: optional precomputed relationships.
        on_stage: optional callback invoked with (stage_name, stage_payload)
            as each pipeline stage completes, enabling real-time progress
            streaming (FR-14 pipeline monitor).

    Returns a single dict containing all analysis products:
      - findings
      - correlations
      - entry point
      - blast radius
      - timeline
      - graph
      - confidence
      - story
      - counts
    """
    event_dicts = [ev.model_dump() for ev in events]
    total = len(events)

    def _emit(stage: str, payload: Optional[Dict] = None):
        if on_stage:
            on_stage(stage, payload or {})

    _emit("started", {"total_events": total})

    # 1. Correlation
    correlations = correlate_events(list(events))
    _emit("correlation", {"pairs": len(correlations)})

    # 2. Suspicious activity detection
    findings = detect_suspicious_activities(list(events))
    _emit("detection", {"findings": len(findings)})

    # Collect suspicious event IDs from findings
    suspicious_event_ids: List[str] = []
    incident_event_ids: List[str] = []
    for f in findings:
        for eid in f.get("related_event_ids", []):
            if eid not in suspicious_event_ids:
                suspicious_event_ids.append(eid)
            # Blast radius should reflect the actual incident, so LOW-severity
            # background findings (e.g. benign off-hours logins) are excluded.
            if f.get("severity") not in ("LOW",) and eid not in incident_event_ids:
                incident_event_ids.append(eid)

    # 3. Initial entry point
    entry_point = find_initial_entry_point(list(events), findings)
    _emit("entry_point", {"event_id": entry_point.get("event_id") if entry_point else None})

    # 4. Relationship graph (BFS attack path from the Initial Entry Point, FR-06.1)
    entry_point_event_id = None
    if entry_point and entry_point.get("event_id"):
        entry_point_event_id = entry_point.get("event_id")
    graph = build_relationship_graph(
        event_dicts,
        relationships_from_db,
        entry_point_event_id=entry_point_event_id,
    )
    _emit("graph", {"nodes": len(graph["nodes"]), "edges": len(graph["edges"])})

    # 5. Blast radius: compromised (FR-08.1) vs at-risk (FR-08.2) tiers based
    #    on the traced attack graph, plus data-flow correlation (FR-07.2).
    blast_radius = calculate_blast_radius(
        list(events),
        incident_event_ids,
        graph=graph,
        entry_point=entry_point,
    )
    _emit("blast_radius", {"hosts": len(blast_radius["hosts"]), "files": len(blast_radius["files"])})

    # 6. Timeline
    timeline = build_timeline(list(events))
    _emit("timeline", {"entries": len(timeline)})

    # 7. Confidence
    confidence = score_investigation_confidence(
        findings,
        correlations,
        len(suspicious_event_ids),
        len(events),
    )
    _emit("confidence", {"score": confidence["score"], "level": confidence["level"]})

    # 8. Risk level
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    risk = risk_level_for(confidence["score"], critical_count)

    # 9. Attack story
    story = generate_attack_story(
        findings,
        entry_point,
        timeline,
        blast_radius,
        confidence,
    )
    _emit("story", {"narrative_chars": len(story["narrative"])})

    _emit("done", {"risk_level": risk})

    return {
        "findings": findings,
        "correlations": correlations,
        "entry_point": entry_point,
        "blast_radius": blast_radius,
        "timeline": timeline,
        "graph": graph,
        "confidence": confidence,
        "risk_level": risk,
        "story": story,
        "counts": {
            "total_events": len(events),
            "suspicious_events": len(suspicious_event_ids),
            "findings": len(findings),
            "correlations": len(correlations),
            "timeline_entries": len(timeline),
            "graph_nodes": len(graph["nodes"]),
            "graph_edges": len(graph["edges"]),
        },
    }