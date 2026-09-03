"""
Initial Entry Point Detection
=============================
Determines the most likely starting point of the attack. It anchors on the
users/IPs identified as suspicious by the detection rules, then locates the
earliest entry-like event (successful login / network connection / process)
that connects to that suspicious activity.

The result is always qualified using cautious language ('likely', 'possible')
and never claims certainty.
"""

from datetime import datetime
from typing import Dict, List, Optional, Set

from app.schemas.schemas import NormalizedEvent
from app.analysis.suspicious_detector import FAILED_LOGIN_BURST_THRESHOLD
from app.utils.helpers import parse_datetime_naive


def _parse_ts(ts_str: str) -> datetime | None:
    return parse_datetime_naive(ts_str)


def find_initial_entry_point(
    events: List[NormalizedEvent],
    findings: List[Dict[str, object]],
) -> Optional[Dict[str, object]]:
    """
    Identify the likely initial entry point event.

    Returns a dict (or None) with:
      {
        "event_id": str,
        "timestamp": str,
        "user": str,
        "source_ip": str,
        "destination_host": str,
        "description": str,
        "confidence": float,
        "reasoning": list[str],         # supporting evidence explanations
        "related_event_ids": list[str],
      }
    """
    if not events:
        return None

    events_by_id = {e.event_id: e for e in events if e.event_id}

    # Gather suspicious users and IPs from the detected findings
    suspicious_users: Set[str] = set()
    suspicious_ips: Set[str] = set()
    for f in findings:
        for eid in f.get("related_event_ids", []):
            ev = events_by_id.get(eid)
            if ev:
                if ev.user:
                    suspicious_users.add(ev.user)
                if ev.source_ip:
                    suspicious_ips.add(ev.source_ip)

    # Strategy 1: first successful login by a suspicious user
    result = _first_successful_login(events, suspicious_users, suspicious_ips)
    if result:
        return result

    # Strategy 2: first network connection from a suspicious IP/user
    result = _first_network_connection(events, suspicious_users, suspicious_ips)
    if result:
        return result

    # Strategy 3: first process execution on a suspicious host
    result = _first_process_exec(events, findings, events_by_id)
    if result:
        return result

    # Strategy 4: earliest event referenced by any finding (fallback)
    result = _earliest_finding_event(findings, events_by_id)
    if result:
        return result

    return None


def _first_successful_login(
    events: List[NormalizedEvent],
    suspicious_users: Set[str],
    suspicious_ips: Set[str],
) -> Optional[Dict[str, object]]:
    """Find the first successful login by a user/IP tied to suspicious activity."""
    candidates = [
        e for e in events
        if "login" in e.action.lower()
        and e.status and "success" in e.status.lower()
        and (e.user in suspicious_users or e.source_ip in suspicious_ips)
    ]
    candidates.sort(key=lambda e: _parse_ts(e.timestamp) or datetime.min)
    if not candidates:
        return None

    ev = candidates[0]
    reasoning = [
        f"Successful login for account '{ev.user}' from {ev.source_ip}.",
        "The account or source IP is associated with suspicious activity detected in the evidence.",
    ]

    # Preceding failures strengthen the entry-point case
    fails = [
        e for e in events
        if "login" in e.action.lower()
        and e.status and "fail" in e.status.lower()
        and e.user == ev.user
        and _parse_ts(e.timestamp) and _parse_ts(ev.timestamp)
        and _parse_ts(e.timestamp) <= _parse_ts(ev.timestamp)
    ]
    confidence = 60.0
    if fails:
        if len(fails) >= FAILED_LOGIN_BURST_THRESHOLD:
            reasoning.append(
                f"Successful login followed {len(fails)} failed attempts for the same account/IP."
            )
            confidence = min(96.0, 72 + len(fails) * 1.5)
        else:
            reasoning.append(f"{len(fails)} earlier failed attempts observed for this account.")
            confidence += 5.0

    related = [f.event_id for f in fails[:5]] + [ev.event_id]

    if len(fails) >= FAILED_LOGIN_BURST_THRESHOLD:
        description = "successful login following sustained brute-force attempts"
    else:
        description = "entry via compromised credentials (suspicious login)"

    return _build_entry(
        ev,
        confidence,
        reasoning,
        related,
        description,
    )


def _first_network_connection(
    events: List[NormalizedEvent],
    suspicious_users: Set[str],
    suspicious_ips: Set[str],
) -> Optional[Dict[str, object]]:
    """Find the first network connection from a suspicious source."""
    candidates = [
        e for e in events
        if e.event_type == "NETWORK_CONNECTION"
        and (e.source_ip in suspicious_ips or e.user in suspicious_users)
    ]
    candidates.sort(key=lambda e: _parse_ts(e.timestamp) or datetime.min)
    if not candidates:
        return None

    ev = candidates[0]
    reasoning = [
        f"First network connection from suspicious source '{ev.source_ip or ev.user}' was observed.",
        "This connection could represent initial access or reconnaissance.",
    ]
    return _build_entry(
        ev,
        65.0,
        reasoning,
        [ev.event_id],
        "network connection from suspicious source",
    )


def _first_process_exec(
    events: List[NormalizedEvent],
    findings: List[Dict[str, object]],
    events_by_id: Dict[str, NormalizedEvent],
) -> Optional[Dict[str, object]]:
    """Find the first suspicious process execution (e.g., credential tooling)."""
    suspicious_users: Set[str] = set()
    suspicious_events: Set[str] = set()
    for f in findings:
        for eid in f.get("related_event_ids", []):
            suspicious_events.add(eid)
            ev = events_by_id.get(eid)
            if ev and ev.user:
                suspicious_users.add(ev.user)

    process_events = [
        e for e in events
        if e.event_type == "PROCESS_EXEC"
    ]
    if not process_events:
        return None

    # Prefer process executions tied to users/events in suspicious findings,
    # otherwise fall back to the earliest process event.
    tied = [
        e for e in process_events
        if e.user in suspicious_users or e.event_id in suspicious_events
    ]
    chosen = tied or process_events
    chosen.sort(key=lambda e: _parse_ts(e.timestamp) or datetime.min)
    ev = chosen[0]
    reasoning = [
        f"First suspicious process execution '{ev.action}' observed on '{ev.source_host or ev.destination_host or 'host'}'.",
        "Atypical process activity on a server can indicate the start of an intrusion.",
    ]
    if tied and ev.user:
        reasoning.append(
            f"Process execution is tied to account '{ev.user}', which is associated with suspicious findings."
        )
    return _build_entry(
        ev,
        60.0 if tied else 58.0,
        reasoning,
        [ev.event_id],
        "suspicious process execution",
    )


def _earliest_finding_event(
    findings: List[Dict[str, object]],
    events_by_id: Dict[str, NormalizedEvent],
) -> Optional[Dict[str, object]]:
    """Fallback: the earliest event referenced by any finding."""
    referenced: List[NormalizedEvent] = []
    for f in findings:
        for eid in f.get("related_event_ids", []):
            ev = events_by_id.get(eid)
            if ev and ev.event_id not in {r.event_id for r in referenced}:
                referenced.append(ev)
    if not referenced:
        return None
    referenced.sort(key=lambda e: _parse_ts(e.timestamp) or datetime.min)
    ev = referenced[0]
    reasoning = [
        "The earliest event linked to the detected suspicious activity was selected.",
        "It predates other related events and may represent the start of the incident.",
    ]
    return _build_entry(
        ev,
        50.0,
        reasoning,
        [r.event_id for r in referenced][:8],
        "earliest event linked to suspicious activity",
    )


def _build_entry(
    event: NormalizedEvent,
    confidence: float,
    reasoning: List[str],
    related: List[str],
    description: str,
) -> Dict[str, object]:
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "user": event.user,
        "source_ip": event.source_ip,
        "destination_host": event.destination_host or event.source_host,
        "description": description,
        "confidence": confidence,
        "reasoning": reasoning,
        "related_event_ids": related,
    }