"""
Tests for Phase 3/4 cross-cutting deliverables:
  * Phase 3 - Story citations (FR-12), audit hash chain (FR-16.2),
              SSE pipeline progress (FR-14).
  * Phase 4 - Externalized YAML config (NFR-M-03 / FR-15.1),
              deterministic parallel ingestion (NFR-P-02 / NFR-R-01),
              Docker packaging (NFR-D-01).
"""
import io
import os

import pytest
from fastapi.testclient import TestClient

import app.config as config_module
from app.utils.parallel import parallel_map
from app.services.evidence_parser import parse_csv
from app.services.normalizer import normalize_event, normalize_events
from app.services.audit_logger import verify_audit_chain
from app.main import app

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# Phase 4 - Externalized YAML configuration (NFR-M-03 / FR-15.1)
# ---------------------------------------------------------------------------

def test_default_config_loaded():
    cfg = config_module.get_config()
    assert cfg.source.endswith("analysis_config.yaml"), f"Unexpected config source: {cfg.source}"
    # Confidence weights present from YAML.
    assert cfg.get("confidence.weights.w_corroboration") == 0.15
    assert cfg.get("confidence.weights.p_conflict_min") == 0.30
    # Detection thresholds present.
    assert cfg.get("detection.brute_force.failed_login_burst_threshold") == 5
    assert cfg.get("detection.brute_force.window_seconds") == 900
    # Correlation + relationship knobs present.
    assert cfg.get("correlation.default_time_window_min") == 10
    assert cfg.get("correlation.data_flow_window_min") == 15
    assert cfg.get("relationships.attack_path_time_window_seconds") == 259200


def test_config_values_match_hardcoded_constants():
    """Externalized values must reproduce the prior hardcoded defaults (NFR-R-01)."""
    from app.analysis import (confidence_scorer as cs,
                              suspicious_detector as sd,
                              correlation_engine as ce,
                              relationship_builder as rb)

    cfg = config_module.get_config()
    assert cs.W_CORROB == cfg.get("confidence.weights.w_corroboration")
    assert cs.W_SPEC == cfg.get("confidence.weights.w_specificity")
    assert cs.P_CONFLICT_MIN == cfg.get("confidence.weights.p_conflict_min")
    assert sd.FAILED_LOGIN_BURST_THRESHOLD == 5
    assert sd.BRUTE_FORCE_WINDOW_SECONDS == 900
    assert sd.EXFIL_THRESHOLD_MB == 100
    assert ce.DEFAULT_TIME_WINDOW_MIN == 10
    assert ce.DATA_FLOW_WINDOW_MIN == 15
    assert rb.ATTACK_PATH_TIME_WINDOW_SECONDS == 72 * 3600


def test_config_tunable_via_env(monkeypatch, tmp_path):
    """An externalized threshold can be tuned without code changes (FR-15.1)."""
    overrides = {
        "confidence": {"weights": {"w_corroboration": 0.33, "p_conflict_min": 0.5}},
        "detection": {"brute_force": {"failed_login_burst_threshold": 99, "window_seconds": 60}},
    }
    cfg_file = tmp_path / "alt_cfg.yaml"
    cfg_file.write_text(_dump_yaml(overrides), encoding="utf-8")

    monkeypatch.setenv("TRACELINE_CONFIG", str(cfg_file))
    config_module._config = None  # force reload
    try:
        cfg = config_module.get_config()
        assert cfg.get("confidence.weights.w_corroboration") == 0.33
        assert cfg.get("detection.brute_force.failed_login_burst_threshold") == 99
        assert cfg.get("detection.brute_force.window_seconds") == 60
    finally:
        config_module._config = None
        monkeypatch.delenv("TRACELINE_CONFIG", raising=False)


def _dump_yaml(data):
    import yaml
    return yaml.safe_dump(data, sort_keys=False)


# ---------------------------------------------------------------------------
# Phase 4 - Deterministic parallel ingestion (NFR-P-02 / NFR-R-01)
# ---------------------------------------------------------------------------

def test_parallel_map_preserves_order():
    """Parallel mapping must return results in input order (deterministic)."""
    items = list(range(0, 120))
    result = parallel_map(lambda x: x * 2, items, min_items=1)
    assert result == [x * 2 for x in items]


def test_parallel_map_equals_sequential():
    """Parallel output must be bit-identical to a linear map."""
    items = [f"row-{i}" for i in range(0, 150)]

    def transform(s):
        return s.upper().replace("-", "_")

    parallel = parallel_map(transform, items, min_items=1)
    sequential = [transform(i) for i in items]
    assert parallel == sequential


def test_parallel_map_small_input_degrades_to_sequential():
    """Below the threshold, parallelism is skipped but result is identical."""
    items = ["a", "b", "c"]
    assert parallel_map(lambda s: s + "!", items, min_items=2000) == ["a!", "b!", "c!"]


def _sample_csv(rows):
    import csv
    buf = io.StringIO()
    fieldnames = ["timestamp", "user", "action", "status"]
    w = csv.DictWriter(buf, fieldnames=fieldnames)
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8")


def test_parse_csv_deterministic_and_sequential_ids():
    """Parser must assign sequential event IDs + correct raw_ref line indices, deterministically."""
    rows = [{"timestamp": f"2026-09-01T08:{i:02d}:00.000000Z",
             "user": f"user{i}", "action": "login", "status": "failed"} for i in range(10)]
    data = _sample_csv(rows)

    r1 = parse_csv(data, "logs.csv")
    r2 = parse_csv(data, "logs.csv")
    assert r1 == r2, "Parsing the same bytes twice must produce identical output"

    ids = [e["event_id"] for e in r1]
    assert ids == [f"EVT-{i:04d}" for i in range(1, 11)], f"Unexpected ids: {ids}"
    # Data rows are 1-indexed starting at line 2 (line 1 = header).
    assert [e["raw_ref"]["line_index"] for e in r1] == list(range(2, 12))
    for e in r1:
        assert e["raw_ref"]["file_hash"], "raw_ref must carry the file SHA-256 hash (FR-02.3)"


def test_normalize_events_matches_sequential():
    """Parallel normalization must equal sequential normalization exactly."""
    raw = [
        {"event_id": f"EVT-{i:04d}", "timestamp": f"2026-09-01T08:{i:02d}:00Z",
         "action": "login", "user": f"u{i}", "status": "failed"}
        for i in range(60)
    ]
    par = normalize_events(raw, source="src.csv")
    seq = [normalize_event(ev, "src.csv") for ev in raw]
    assert [p.model_dump() for p in par] == [s.model_dump() for s in seq]


# ---------------------------------------------------------------------------
# Phase 4 - Docker packaging (NFR-D-01 / NFR-D-02)
# ---------------------------------------------------------------------------

def test_docker_artifacts_present():
    compose = os.path.join(BACKEND_DIR, "..", "docker-compose.yml")
    assert os.path.isfile(compose)
    with open(compose, "r", encoding="utf-8") as f:
        content = f.read()
    assert "traceline-api" in content and "traceline-ui" in content, \
        "compose must define the two required containers"

    assert os.path.isfile(os.path.join(BACKEND_DIR, "Dockerfile"))
    assert os.path.isfile(os.path.join(BACKEND_DIR, "..", "frontend", "Dockerfile"))
    assert os.path.isfile(os.path.join(BACKEND_DIR, "..", "frontend", "nginx.conf"))


# ---------------------------------------------------------------------------
# Phase 3 - Story citations (FR-12), audit chain (FR-16.2), SSE (FR-14)
# ---------------------------------------------------------------------------

def test_story_narrative_has_citations_and_inference_marks(client):
    """FR-12: narrative must cite evidence [Ref: EVT-xxxx] and tag unverified claims."""
    client.post("/api/scenarios/data_theft/load")
    rep = client.get("/api/report?investigation_id=1").json()
    story = rep["attack_story"]
    assert "[Ref:" in story["narrative"], "Narrative must include inline evidence citations (FR-12.2)"
    assert "[Inferred / Unverified]" in story["narrative"], \
        "Narrative must tag unverified claims (FR-12.3)"
    # Fact vs inference strictness: an "Observed evidence confirms" phrasing exists.
    assert "Observed evidence confirms" in story["narrative"]
    assert len(story["limitations"]) > 0


def test_audit_chain_integrity(client):
    """FR-16.2: the append-only audit log must verify as a tamper-evident chain.

    Records are stored in the ``audit_log`` table (serverless-friendly) and
    chained via SHA-256 hashes. Verifying the chain detects tampering.
    """
    from app.services import audit_logger
    audit_logger.reset_audit_log()
    try:
        audit_logger.log_action(action="test_action", investigation_id=1, details={"k": "v"})
        audit_logger.log_action(action="test_action_2", investigation_id=2, details={"x": 1})
        result = verify_audit_chain()
        assert result["intact"] is True, f"Audit chain must be intact, result={result}"
        assert result["broken"] == 0
        assert result["total_records"] == 2
    finally:
        audit_logger.reset_audit_log()


def test_sse_progress_streams_pipeline_stages(client):
    """FR-14: the /api/analysis/progress endpoint must stream pipeline stages."""
    client.post("/api/scenarios/brute_force/load")
    with client.stream("GET", "/api/analysis/progress?investigation_id=1") as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")
        body = "".join(resp.iter_text())
    stages = [line[len("data: "):] for line in body.splitlines() if line.startswith("data: ")]
    assert stages, "Expected at least one SSE frame"
    import json
    names = []
    for s in stages:
        names.append(json.loads(s)["stage"])
    # The pipeline must reach the terminal 'done' stage.
    assert "done" in names
    for expected in ("correlation", "detection", "graph", "blast_radius", "story"):
        assert expected in names, f"Missing pipeline stage {expected} in {names}"
