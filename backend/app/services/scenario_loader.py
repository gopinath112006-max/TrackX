"""Scenario data loader."""
import json
import os
from typing import Dict, List, Optional

_SERVICES_DIR = os.path.dirname(os.path.abspath(__file__))


def _scenarios_dir() -> Optional[str]:
    """Return the first existing scenarios directory.

    Prefer the bundled location (backend/data/scenarios) used when the
    backend is deployed as a Vercel service whose root is backend/, then
    fall back to the legacy repo-root data/scenarios path.
    """
    for rel in ("..", "..", "data", "scenarios"), ("..", "..", "..", "data", "scenarios"):
        candidate = os.path.abspath(os.path.join(_SERVICES_DIR, *rel))
        if os.path.isdir(candidate):
            return candidate
    return None


def list_scenarios() -> List[Dict[str, object]]:
    """Return metadata for all available demo scenarios."""
    scenarios = []
    scenarios_dir = _scenarios_dir()
    if not scenarios_dir:
        return scenarios
    for entry in sorted(os.listdir(scenarios_dir)):
        dir_path = os.path.join(scenarios_dir, entry)
        if not os.path.isdir(dir_path):
            continue
        meta_path = os.path.join(dir_path, "scenario.json")
        if not os.path.isfile(meta_path):
            continue
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        data_files = [
            fi for fi in os.listdir(dir_path)
            if fi.endswith((".csv", ".json", ".txt"))
        ]
        scenarios.append({
            "id": meta.get("id", entry),
            "name": meta.get("name", entry),
            "description": meta.get("description", ""),
            "category": meta.get("category", "unknown"),
            "event_count": _count_events(dir_path, data_files),
            "expected_findings": meta.get("expected_findings", []),
            "files": data_files,
        })
    return scenarios


def _infer_category(filename: str) -> str:
    """Infer an evidence-source category from the file name."""
    name = filename.lower()
    if "login" in name or "auth" in name:
        return "login"
    if "network" in name or "firewall" in name:
        return "network"
    if "file" in name:
        return "file_access"
    if "system" in name or "process" in name:
        return "system"
    return "system"


def get_scenario_files(scenario_id: str) -> List[Dict[str, str]]:
    """
    Return the list of data file paths (with category info) for a scenario.
    """
    scenario_dir = _scenario_dir(scenario_id)
    if not scenario_dir:
        return []
    files = []
    for fi in sorted(os.listdir(scenario_dir)):
        if not fi.endswith((".csv", ".json", ".txt")):
            continue
        files.append({
            "filename": fi,
            "path": os.path.join(scenario_dir, fi),
            "category": _infer_category(fi),
        })
    return files


def _scenario_dir(scenario_id: str):
    scenarios_dir = _scenarios_dir()
    if not scenarios_dir:
        return None
    path = os.path.join(scenarios_dir, scenario_id)
    return path if os.path.isdir(path) else None


def _count_events(dir_path: str, data_files: List[str]) -> int:
    """Approximate total event count from the header rows of CSV files."""
    import csv
    total = 0
    for fi in data_files:
        if not fi.endswith(".csv"):
            continue
        try:
            with open(os.path.join(dir_path, fi), "r", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                first = True
                for _ in reader:
                    if first:
                        first = False
                        continue
                    total += 1
        except (OSError, csv.Error):
            continue
    return total