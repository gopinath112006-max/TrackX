"""
Correlation Engine
==================
The core of the investigation. Connects related evidence events using
several heuristic factors and produces an explainable correlation score.

Scoring model:
  - same_user               = +25
  - same_source_ip          = +25
  - close_timestamp         = +20  (within a configurable window, default 10 min)
  - same_host               = +15  (source or destination)
  - related_action_sequence = +15  (e.g., failed login -> successful login -> file access)
  - cross_source            = +10  (events corroborated by independent evidence sources)

Maximum score = 100. Classification:
  80-100 = High confidence
  50-79  = Medium confidence
  0-49   = Low confidence
"""

from datetime import datetime
from typing import Dict, List, Tuple

from app.schemas.schemas import NormalizedEvent
from app.utils.helpers import parse_datetime_naive
from app.config import conf_int

# Default correlation time window in minutes (externalized)
DEFAULT_TIME_WINDOW_MIN = conf_int("correlation.default_time_window_min", 10)

# Bonus applied when two correlated events come from independent evidence
# sources (e.g., a login log corroborated by a network log).
CROSS_SOURCE_BONUS = conf_int("correlation.cross_source_bonus", 10)

# Related event-sequence patterns keyed by (previous_event_type, following_event_type)
_ACTION_SEQUENCE_PAIRS = {
    ("LOGIN", "LOGIN"): "sequential login events",
    ("LOGIN", "FILE_ACCESS"): "login followed by file access",
    ("LOGIN", "FILE_DOWNLOAD"): "login followed by file download",
    ("LOGIN", "DATA_TRANSFER"): "login followed by data transfer",
    ("FILE_ACCESS", "FILE_DOWNLOAD"): "file access followed by download",
    ("FILE_ACCESS", "DATA_TRANSFER"): "file access followed by data transfer",
    ("LOGIN", "NETWORK_CONNECTION"): "login followed by network connection",
    ("NETWORK_CONNECTION", "NETWORK_CONNECTION"): "sequential network connections",
    ("FILE_DOWNLOAD", "DATA_TRANSFER"): "download followed by outbound transfer",
    ("LOGIN", "PROCESS_EXEC"): "login followed by process execution",
}

# Event pairs that indicate lateral movement (access on multiple systems)
_LATERAL_PAIRS = {
    ("LOGIN", "LOGIN"),
}

# Data-flow correlation window used to link host file access to network egress
# (FR-07.2).
DATA_FLOW_WINDOW_MIN = conf_int("correlation.data_flow_window_min", 15)

# Event types that represent reading/staging data on a host.
_HOST_READ_TYPES = {"FILE_ACCESS", "FILE_READ", "FILE_DOWNLOAD"}
# Event types that represent transferring data off a host (network egress).
_EGRESS_TYPES = {"DATA_TRANSFER", "FILE_UPLOAD"}


def _parse_ts(timestamp_str: str) -> datetime | None:
    """Parse a normalized timestamp string into a naive UTC datetime object."""
    return parse_datetime_naive(timestamp_str)


def _within_time_window(ts_a: str, ts_b: str, window_min: int) -> bool:
    """Check whether two timestamps are within the given window."""
    a = _parse_ts(ts_a)
    b = _parse_ts(ts_b)
    if a is None or b is None:
        return False
    delta = abs((b - a).total_seconds())
    return delta <= window_min * 60


def correlate_events(
    events: List[NormalizedEvent],
    window_min: int = DEFAULT_TIME_WINDOW_MIN,
) -> List[Dict[str, object]]:
    """
    Compute pairwise correlation scores between all events.

    Returns a list of dicts:
      {
        "event_a_event_id": str,
        "event_b_event_id": str,
        "score": float,
        "factors": list[str],
      }
    """
    results: List[Dict[str, object]] = []

    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            a = events[i]
            b = events[j]

            score = 0
            factors: List[str] = []

            # Same user
            if a.user and b.user and a.user.lower() == b.user.lower():
                score += 25
                factors.append("same_user")

            # Same source IP
            if a.source_ip and b.source_ip and a.source_ip == b.source_ip:
                score += 25
                factors.append("same_source_ip")

            # Close timestamp
            if _within_time_window(a.timestamp, b.timestamp, window_min):
                score += 20
                factors.append("close_timestamp")

            # Same host (source or destination)
            same_host = False
            if a.destination_host and b.destination_host and a.destination_host.lower() == b.destination_host.lower():
                same_host = True
            if a.source_host and b.source_host and a.source_host.lower() == b.source_host.lower():
                same_host = True
            if same_host:
                score += 15
                factors.append("same_host")

            # Related action sequence
            seq_desc = _ACTION_SEQUENCE_PAIRS.get((a.event_type, b.event_type))
            if not seq_desc:
                seq_desc = _ACTION_SEQUENCE_PAIRS.get((b.event_type, a.event_type))
            if seq_desc:
                score += 15
                factors.append("related_action_sequence")

            # Cross-source corroboration: same behavior visible in two
            # independent evidence sources (different log files) is stronger
            # evidence than a signal seen in a single source.
            if a.source and b.source and a.source != b.source:
                score += CROSS_SOURCE_BONUS
                factors.append("cross_source_corroboration")

            # Only keep pairs that have at least some relationship (score > 0)
            if score > 0:
                results.append({
                    "event_a_event_id": a.event_id,
                    "event_b_event_id": b.event_id,
                    "score": min(score, 100),
                    "factors": factors,
                })

    # FR-07.2: Data-flow correlation (host file access -> network egress).
    results.extend(_correlate_data_flows(events, window_min))

    return results


def _correlate_data_flows(
    events: List[NormalizedEvent],
    window_min: int,
) -> List[Dict[str, object]]:
    """Correlate host file access with subsequent network egress (FR-07.2).

    Links a file-access/read/staging event on a host to a later network
    egress (data transfer / file upload) from the same host or user within
    the data-flow window. This exposes the exfiltration chain: a sensitive
    file read on a host, then transferred off the network.
    """
    results: List[Dict[str, object]] = []
    window = window_min or DATA_FLOW_WINDOW_MIN

    reads = [e for e in events if e.event_type in _HOST_READ_TYPES]
    egress = [e for e in events if e.event_type in _EGRESS_TYPES]

    for rd in reads:
        rd_host = rd.destination_host or rd.source_host
        for eg in egress:
            eg_host = eg.source_host or eg.destination_host
            # Same host OR same user performing both the read and the egress.
            same_host = rd_host and eg_host and rd_host.lower() == eg_host.lower()
            same_user = rd.user and eg.user and rd.user.lower() == eg.user.lower()
            if not (same_host or same_user):
                continue

            ta = _parse_ts(rd.timestamp)
            tb = _parse_ts(eg.timestamp)
            if ta is None or tb is None:
                continue
            if tb < ta:
                continue  # egress must follow the read
            if (tb - ta).total_seconds() > window * 60:
                continue

            score = 70
            factors = ["host_to_network_data_flow"]
            if same_host:
                factors.append("same_host")
            if same_user:
                factors.append("same_user")
            factors.append("close_timestamp")

            results.append({
                "event_a_event_id": rd.event_id,
                "event_b_event_id": eg.event_id,
                "score": score,
                "factors": factors,
                "correlation_type": "data_flow",
            })

    return results


def confidence_level(score: float) -> str:
    """Classify a correlation score into a high/medium/low label."""
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"
