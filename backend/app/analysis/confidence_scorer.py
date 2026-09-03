"""
Confidence Scoring
==================
Computes transparent, deterministic confidence scores using the documented
multi-factor formula (FR-10.1, FR-10.3):

    C = min(1.0, BaseScore + w_corrob * (N_sources - 1)
                  + w_spec * S_pattern
                  - P_gap - P_conflict)

  * BaseScore     : starting trust from the severity/type of the finding.
  * w_corrob      : weight of each independent corroborating log source
                    beyond the first (default 0.15).
  * N_sources     : number of independent evidence sources supporting the
                    finding.
  * w_spec        : weight of pattern specificity (default 0.15).
  * S_pattern     : specificity of the matched signature in [0.0, 1.0].
  * P_gap         : penalty for temporal gaps / inferred hops.
  * P_conflict    : penalty (>= 0.30) for conflicting/anti-forensic telemetry
                    (FR-10.3).

Classification (FR-10.1):
  * HIGH   : C >= 0.80
  * MEDIUM : 0.50 <= C < 0.80
  * LOW    : C < 0.50

Every finding also receives a machine-generated `confidence_rationale`
(FR-10.2) describing exactly which boosters/penalties were applied.
"""

from typing import Dict, List

from app.config import conf_dict, conf_float, conf_int


# --- Formula constants (externalized: config/analysis_config.yaml) ----------
W_CORROB = conf_float("confidence.weights.w_corroboration", 0.15)
W_SPEC = conf_float("confidence.weights.w_specificity", 0.15)
P_GAP_DEFAULT = conf_float("confidence.weights.p_gap_default", 0.10)
P_CONFLICT_MIN = conf_float("confidence.weights.p_conflict_min", 0.30)

# A horizon (seconds) beyond which two events are treated as temporally gapped.
GAP_THRESHOLD_SECONDS = conf_int("confidence.gap_threshold_seconds", 3600)


def base_score_for(severity: str) -> float:
    """Starting BaseScore for a finding based on its severity/type."""
    scores = conf_dict("confidence.base_scores", {})
    return float(scores.get(severity.upper(), scores.get("default", 0.50)))


def specificity_for(pattern_category: str) -> float:
    """Pattern specificity S_pattern for a finding category.

    Highly specific signatures (brute-force bursts, volume exfiltration)
    score higher than generic ones (off-hours access).
    """
    specific = conf_dict("confidence.specificity", {})
    return float(specific.get(pattern_category, specific.get("default", 0.5)))


def compute_confidence_score(
    base_score: float,
    n_sources: int = 1,
    specificity: float = 0.5,
    gap_penalty: float = 0.0,
    conflict_penalty: float = 0.0,
    rationale: List[str] | None = None,
) -> float:
    """Apply the documented confidence formula and return a score in [0,1]."""
    corrob = W_CORROB * max(0, n_sources - 1)
    spec = W_SPEC * specificity
    c = base_score + corrob + spec - gap_penalty - conflict_penalty
    c = max(0.0, min(1.0, c))

    if rationale is not None:
        if n_sources > 1:
            rationale.append(
                f"corroborated by {n_sources} independent log source(s) (+{corrob:.2f})"
            )
        if specificity > 0:
            rationale.append(
                f"signature specificity {specificity:.1f} (+{spec:.2f})"
            )
        if gap_penalty > 0:
            rationale.append(f"temporal gap penalty (-{gap_penalty:.2f})")
        if conflict_penalty > 0:
            rationale.append(f"conflicting telemetry penalty (-{conflict_penalty:.2f})")
    return round(c, 4)


def label_for(confidence: float) -> str:
    """Map a numeric score to its discrete confidence label."""
    labels = conf_dict("confidence.label", {})
    high_min = float(labels.get("high_min", 0.80))
    medium_min = float(labels.get("medium_min", 0.50))
    if confidence >= high_min:
        return "HIGH"
    if confidence >= medium_min:
        return "MEDIUM"
    return "LOW"


def detect_conflict_penalty(
    related_event_ids: List[str],
    correlations: List[Dict],
) -> float:
    """Detect conflicting/anti-forensic telemetry (FR-10.3).

    A conflict penalty (>= 0.30) is deducted when the same finding is
    corroborated by evidence that is mutually contradictory, e.g. process
    termination reported by a host log while network flows for the same host
    remain active, or simultaneous logins from distant locations. Here we
    conservative-detect a conflict when a finding's supporting events span
    several independent sources that report contradictory status fields.
    """
    if not related_event_ids:
        return 0.0
    event_ids = set(related_event_ids)

    # Gather correlation records that explicitly reference this finding's
    # events and flag known conflict patterns in their factor explanations.
    for c in correlations:
        f = " ".join(c.get("factors", []))
        if event_ids and (
            c.get("event_a_event_id") in event_ids
            or c.get("event_b_event_id") in event_ids
        ):
            if "conflict" in f.lower() or "contradict" in f.lower():
                return P_CONFLICT_MIN
    return 0.0


def score_finding_confidence(
    severity: str,
    event_count: int,
    supporting_factors: List[str] | None = None,
    category: str = "unusual_login",
    n_sources: int = 1,
) -> float:
    """
    Compute a single finding's confidence from its severity and how much
    related evidence it references, using the documented formula.
    """
    supporting_factors = supporting_factors or []
    # Infer corroborating sources from explicit cross-source evidence (if the
    # calling code provided any source hints); otherwise default to the
    # supplied `n_sources`.
    n = n_sources
    if "correlation" in supporting_factors:
        n = max(n, 2)

    base = base_score_for(severity)
    spec = specificity_for(category)
    rationale: List[str] = []
    score = compute_confidence_score(
        base_score=base,
        n_sources=n,
        specificity=spec,
        rationale=rationale,
    )
    # The documented formula yields [0,1]; the API surfaces confidence as a
    # 0-100 percentage for consistency with the existing presentation layer.
    return round(score * 100, 1)


def score_investigation_confidence(
    findings: List[Dict],
    correlations: List[Dict],
    suspicious_events: int,
    total_events: int,
) -> Dict[str, object]:
    """
    Compute the overall investigation confidence using the documented formula.

    Returns a dict with the score (0-100), an explanation of contributing
    factors, and the level.
    """
    if total_events == 0:
        return {"score": 0.0, "factors": ["No evidence available"], "level": "LOW"}

    rationale: List[str] = []

    # BaseScore: normalized by how much of the evidence is suspicious.
    base = 0.30 + 0.30 * (suspicious_events / total_events)
    rationale.append(
        f"base signal from {suspicious_events}/{total_events} suspicious evidence events"
    )

    # Corroborating sources: count distinct evidence sources touched by
    # findings, plus cross-source correlated pairs.
    sources: set = set()
    pattern_terms = 0.0
    finding_event_ids = set()
    for f in findings:
        cat = f.get("category", "unusual_login")
        sources.update(f.get("sources", []) or [])
        finding_event_ids.update(f.get("related_event_ids", []) or [])
        # High/medium specificity adds to the overall pattern term.
        pattern_terms += specificity_for(cat) * min(0.5, f.get("confidence", 50) / 100)
    n_sources = max(1, len(sources))

    # Cross-source corroboration: legitimate when a finding's events are
    # linked to events from an independent log source. Count distinct source
    # pairs referenced by the correlated findings, not raw pair totals.
    corroborated_source_pairs: set = set()
    for c in correlations:
        if "cross_source_corroboration" not in c.get("factors", []):
            continue
        if c.get("event_a_event_id") in finding_event_ids or c.get("event_b_event_id") in finding_event_ids:
            corroborated_source_pairs.add((c.get("event_a_event_id"), c.get("event_b_event_id")))
    if corroborated_source_pairs:
        n_sources = max(n_sources, 2)
        rationale.append(
            f"{len(corroborated_source_pairs)} evidence pair(s) corroborated across independent log sources"
        )

    # Aggregated conflict penalty across findings.
    conflict = 0.0
    for f in findings:
        conflict = max(
            conflict,
            detect_conflict_penalty(f.get("related_event_ids", []), correlations),
        )
    if conflict > 0:
        rationale.append(f"conflicting telemetry across findings (-{conflict:.2f})")

    # Aggregated gap penalty when suspicious ratio is low or few correlations.
    gap = P_GAP_DEFAULT if suspicious_events == 0 or not correlations else 0.0
    if gap:
        rationale.append("temporal gaps / unlinked evidence (-{:.2f})".format(gap))

    score = compute_confidence_score(
        base_score=base,
        n_sources=n_sources,
        specificity=min(1.0, pattern_terms),
        gap_penalty=gap,
        conflict_penalty=conflict,
        rationale=rationale,
    )

    return {
        "score": round(score * 100, 1),
        "factors": rationale,
        "level": label_for(score),
    }


def risk_level_for(confidence_score: float, critical_findings: int = 0) -> str:
    """Map an overall confidence to a risk level for display purposes."""
    risk = conf_dict("confidence.risk", {})
    high_min = float(risk.get("high_confidence_min", 75))
    medium_min = float(risk.get("medium_confidence_min", 50))
    if critical_findings > 0 or confidence_score >= high_min:
        return "HIGH"
    if confidence_score >= medium_min:
        return "MEDIUM"
    return "LOW"
