"""End-to-end tests for all demo scenarios."""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.scenario_loader import get_scenario_files
from app.services import analysis_store
from app.models import Finding, Correlation, TimelineEntry, Relationship
from app.dependencies import get_db

ALL_SCENARIOS = [
    "brute_force",
    "data_theft",
    "lateral_movement",
    "stolen_credentials",
]


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_scenario_end_to_end(client, scenario_id):
    """Load each scenario and verify the full analysis pipeline works."""
    resp = client.post(f"/api/scenarios/{scenario_id}/load")
    assert resp.status_code == 200
    data = resp.json()
    inv_id = data["investigation_id"]
    assert data["findings_count"] > 0, "Expected at least one finding"

    # Events are loaded and retrievable
    events = client.get(f"/api/events?investigation_id={inv_id}")
    assert events.status_code == 200
    assert len(events.json()) > 0, "Events must be loaded"

    # Findings are present and reference evidence
    findings = client.get(f"/api/findings?investigation_id={inv_id}")
    assert findings.status_code == 200
    f_list = findings.json()
    assert len(f_list) > 0
    for f in f_list:
        assert f["related_event_ids"], "Finding must reference evidence events"
        assert f["reason"], "Finding must have an explanation"
        assert 0 < f["confidence"] <= 100

    # Investigation overview
    inv = client.get(f"/api/investigation?investigation_id={inv_id}").json()
    assert inv["confidence"]["score"] > 0
    assert inv["blast_radius"]
    assert inv["counts"]["timeline_entries"] > 0

    # Timeline
    tl = client.get(f"/api/timeline?investigation_id={inv_id}")
    assert tl.status_code == 200
    assert tl.json()["total_count"] > 0

    # Relationship graph
    rels = client.get(f"/api/relationships?investigation_id={inv_id}")
    assert rels.status_code == 200
    graph = rels.json()
    assert graph["nodes"] and graph["edges"]

    # Every relationship edge must carry its supporting evidence, and the
    # hidden-relationship inference pass must surface derived links.
    for e in graph["edges"]:
        assert e["evidence_event_ids"], "Relationship edge must reference evidence events"
    assert any(e.get("inferred") for e in graph["edges"]), "Expected inferred (hidden) relationships"

    # Correlations
    corr = client.get(f"/api/correlations?investigation_id={inv_id}")
    assert corr.status_code == 200
    corr_list = corr.json()
    assert len(corr_list) > 0, "Expected correlated event pairs"
    for c in corr_list:
        assert c["factors"], "Correlation must explain why events are linked"
    # Evidence collected from multiple independent sources must produce
    # cross-source corroborated pairs.
    assert any(
        "cross_source_corroboration" in c["factors"] for c in corr_list
    ), "Expected cross-source correlated pairs"

    # Report data
    rep = client.get(f"/api/report?investigation_id={inv_id}")
    assert rep.status_code == 200
    story = rep.json()["attack_story"]
    assert len(story["narrative"]) > 50

    # HTML report
    html = client.get(f"/api/report/html?investigation_id={inv_id}")
    assert html.status_code == 200
    assert "<html" in html.text.lower()


@pytest.mark.parametrize("scenario_id", ALL_SCENARIOS)
def test_scenario_files_are_categorized(client, scenario_id):
    """Every demo scenario log file must carry a meaningful evidence category."""
    files = get_scenario_files(scenario_id)
    assert files, f"Scenario '{scenario_id}' must have data files"
    for f in files:
        assert f.get("category"), f"'{f['filename']}' is missing an evidence category"
    categories = {f["category"] for f in files}
    assert len(categories) >= 2, "Scenario evidence should span multiple categories"
    assert "system" not in categories or len(categories) > 1, \
        "Scenario files must not all default to the 'system' category"


def test_brute_force_scenario_expected_findings(client):
    """Brute force scenario must detect the brute force compromise."""
    client.post("/api/scenarios/brute_force/load")
    inv_id = 1
    findings = client.get(f"/api/findings?investigation_id={inv_id}").json()
    titles = [f["title"].lower() for f in findings]
    assert any("brute-force" in t for t in titles), "Brute force finding expected"
    inv = client.get(f"/api/investigation?investigation_id={inv_id}").json()
    assert inv["entry_point"] is not None
    assert "brute" in inv["entry_point"]["description"].lower()


def test_data_theft_scenario_expected_findings(client):
    """Data theft scenario must detect sensitive-file collection/exfiltration."""
    data = client.post("/api/scenarios/data_theft/load").json()
    inv_id = data["investigation_id"]
    findings = client.get(f"/api/findings?investigation_id={inv_id}").json()
    titles = [f["title"].lower() for f in findings]
    assert any("data collection" in t or "exfiltration" in t for t in titles), \
        f"Expected data-collection/exfiltration finding, got {titles}"
    inv = client.get(f"/api/investigation?investigation_id={inv_id}").json()
    assert "customer" in " ".join(inv["blast_radius"]["files"]).lower() or \
        "password" in " ".join(inv["blast_radius"]["files"]).lower(), "Sensitive files expected in blast radius"


def test_lateral_movement_scenario_expected_findings(client):
    """Lateral movement scenario must detect multiple affected systems."""
    data = client.post("/api/scenarios/lateral_movement/load").json()
    inv_id = data["investigation_id"]
    findings = client.get(f"/api/findings?investigation_id={inv_id}").json()
    titles = [f["title"].lower() for f in findings]
    assert any("lateral movement" in t for t in titles), f"Lateral movement finding expected, got {titles}"
    inv = client.get(f"/api/investigation?investigation_id={inv_id}").json()
    assert len(inv["blast_radius"]["hosts"]) >= 2, "Multiple affected hosts expected"


def test_stolen_credentials_scenario_expected_findings(client):
    """Stolen-credentials scenario must detect a login from a single-use public IP."""
    data = client.post("/api/scenarios/stolen_credentials/load").json()
    inv_id = data["investigation_id"]
    findings = client.get(f"/api/findings?investigation_id={inv_id}").json()
    titles = [f["title"].lower() for f in findings]
    assert any("suspicious login" in t for t in titles), \
        f"Rule 2 (suspicious login source) finding expected, got {titles}"
    inv = client.get(f"/api/investigation?investigation_id={inv_id}").json()
    assert inv["entry_point"] is not None
    assert inv["entry_point"]["source_ip"] == "198.51.100.23", \
        "Entry point should be the external (single-use public) IP"
    assert "sensitive" in " ".join(titles), "Sensitive-file access finding expected"
    assert any("data collection" in t for t in titles), "Data-collection finding expected"


def test_all_detection_rules_covered(client):
    """All 7 detection-rule categories must be exercised across the scenario suite."""
    required = {
        "brute_force",
        "unusual_login",
        "sensitive_access",
        "data_collection",
        "exfiltration",
        "lateral_movement",
        "unusual_time",
    }
    seen = set()
    for scenario_id in ALL_SCENARIOS:
        data = client.post(f"/api/scenarios/{scenario_id}/load").json()
        inv_id = data["investigation_id"]
        for f in client.get(f"/api/findings?investigation_id={inv_id}").json():
            seen.add(f["category"])
    missing = required - seen
    assert not missing, f"Detection rules not covered by any scenario: {missing}"


def test_analysis_persisted_to_db(client):
    """Analysis products must be persisted to the SQLite analysis tables."""
    data = client.post("/api/scenarios/brute_force/load").json()
    inv_id = data["investigation_id"]
    with next(get_db()) as db:
        assert db.query(Finding).filter_by(investigation_id=inv_id).count() > 0
        assert db.query(Correlation).filter_by(investigation_id=inv_id).count() > 0
        assert db.query(TimelineEntry).filter_by(investigation_id=inv_id).count() > 0
        assert db.query(Relationship).filter_by(investigation_id=inv_id).count() > 0


def test_analysis_restored_after_cache_clear(client):
    """Analysis must be served from SQLite after the in-memory cache is cleared."""
    data = client.post("/api/scenarios/data_theft/load").json()
    inv_id = data["investigation_id"]
    analysis_store.clear_analysis(inv_id)

    for endpoint in (
        f"/api/findings?investigation_id={inv_id}",
        f"/api/timeline?investigation_id={inv_id}",
        f"/api/relationships?investigation_id={inv_id}",
        f"/api/investigation?investigation_id={inv_id}",
        f"/api/report?investigation_id={inv_id}",
    ):
        resp = client.get(endpoint)
        assert resp.status_code == 200, f"Expected 200 for {endpoint}, got {resp.status_code}"

    # The investigations list must restore findings from SQLite too.
    inv_list = client.get("/api/investigations").json()
    restored = next((i for i in inv_list if i["id"] == inv_id), None)
    assert restored is not None, "Investigation missing from list"
    assert restored["total_findings"] > 0, "Findings should be restored from SQLite"