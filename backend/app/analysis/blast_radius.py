"""
Blast Radius Analysis
=====================
Determines the scope of the incident and categorizes assets into two tiers
per the specification:

  * COMPROMISED (FR-08.1) - physical, logical, and identity assets directly
    manipulated by the adversary along the traced attack path. These are the
    unique node entities in the confirmed attack sub-graph that carry a
    malicious action edge.
  * AT_RISK (FR-08.2) - assets that share credentials, trust relationships,
    or direct network reachability with confirmed compromised assets but have
    no confirmed breach events of their own. Computed via a 1-hop reachability
    expansion across identity/subnet trust edges.

The result also aggregates a data-flow correlation summary (FR-07.2),
linking host file access to subsequent network egress from the same host/user.

For backwards compatibility the response keeps the aggregate `users`, `ips`,
`hosts`, `files`, and `total_affected` fields that the UI and report layers
consume, while adding the tiered `compromised`/`at_risk` structures.
"""

from typing import Dict, List, Set

from app.schemas.schemas import NormalizedEvent


def _label_from_node_id(node_id: str) -> str:
    """Recover the display label from a `TYPE||label` node id."""
    if "||" in node_id:
        return node_id.split("||", 1)[1]
    return node_id


def _subnet(host_ip: str) -> str | None:
    """Return the /24 subnet of an IPv4 address, or None if not parseable."""
    parts = host_ip.split(".")
    if len(parts) != 4:
        return None
    try:
        [int(p) for p in parts]
    except ValueError:
        return None
    return ".".join(parts[:3]) + ".0/24"


def calculate_blast_radius(
    events: List[NormalizedEvent],
    suspicious_event_ids: List[str],
    graph: Dict[str, List[Dict]] | None = None,
    entry_point: Dict | None = None,
) -> Dict[str, object]:
    """
    Compute the blast radius, categorized into compromised and at-risk tiers.

    Args:
        events: all normalized events.
        suspicious_event_ids: event IDs implicated in the incident.
        graph: the traced relationship graph from `build_relationship_graph`
            (nodes tagged with `on_attack_path` identify the confirmed attack
            sub-graph used for FR-08.1).
        entry_point: the entry-point finding (used to anchor the attack path).

    Returns:
        A dict with `compromised`, `at_risk`, `data_flows`, and the aggregate
        legacy fields (`users`, `ips`, `hosts`, `files`, `total_affected`).
    """
    event_id_set = set(suspicious_event_ids)
    incident_events = [e for e in events if e.event_id in event_id_set]
    if not incident_events:
        incident_events = [
            e for e in events if e.severity in ("HIGH", "CRITICAL", "MEDIUM")
        ]
    incident_event_ids = {e.event_id for e in incident_events}

    # ---------- FR-08.1: Confirmed compromised assets ----------------------
    compromised: Dict[str, Set[str]] = {
        "users": set(), "ips": set(), "hosts": set(), "files": set(),
    }
    compromised_evidence: Dict[str, List[str]] = {}

    def _record_compromised(kind: str, label: str, eid: str):
        if not label:
            return
        compromised[kind].add(label)
        compromised_evidence.setdefault(f"{kind}||{label}", []).append(eid)

    # On the attack path, tag-only (passive) nodes are inspected rather than
    # compromised; only nodes with a direct malicious action edge count.
    attack_path_node_ids: Set[str] = set()
    if graph:
        for n in graph.get("nodes", []):
            if n.get("on_attack_path"):
                attack_path_node_ids.add(n["id"])

        # Collect the direct evidence each attack-path node is attached to.
        for e in graph.get("edges", []):
            if not e.get("on_attack_path"):
                continue
            ev_ids = e.get("evidence_event_ids") or []

    # For each attacker-controlled event on the attack path, mark the entities
    # it manipulates as compromised (they carry a malicious action edge).
    for e in incident_events:
        _record_compromised("users", e.user, e.event_id)
        _record_compromised("ips", e.source_ip, e.event_id)
        _record_compromised("ips", e.destination_ip, e.event_id)
        _record_compromised("hosts", e.destination_host, e.event_id)
        _record_compromised("hosts", e.source_host, e.event_id)
        _record_compromised("files", e.file_path, e.event_id)

    # ---------- FR-08.2: Reachable at-risk assets --------------------------
    at_risk: Dict[str, Set[str]] = {"users": set(), "ips": set(), "hosts": set()}
    at_risk_rationale: Dict[str, str] = {}

    comp_hosts = compromised["hosts"]
    comp_users = compromised["users"]
    comp_ips = compromised["ips"]

    # 1-hop identity expansion: any host sharing a compromised user, and any
    # user sharing an IP with a compromised user, is at-risk.
    for ev in events:
        usr = ev.user
        host = ev.destination_host or ev.source_host
        ip = ev.source_ip or ev.destination_ip

        if host and comp_users and usr and usr in comp_users and host not in comp_hosts:
            at_risk["hosts"].add(host)
            at_risk_rationale.setdefault(
                f"hosts||{host}",
                f"Shares an identity used by compromised account '{usr}'",
            )
        if usr and comp_ips and ip and ip in comp_ips and usr not in comp_users:
            at_risk["users"].add(usr)
            at_risk_rationale.setdefault(
                f"users||{usr}",
                f"Originated from compromised source '{ip}'",
            )

    # 1-hop subnet expansion: hosts on the same /24 subnet as a compromised
    # host are at-risk (inferred topology, FR-08.2 failure handling).
    comp_subnets = {_subnet(h) for h in comp_hosts if _subnet(h)}
    for ev in events:
        host = ev.destination_host or ev.source_host
        ip = ev.destination_ip or ev.source_ip
        if host and host not in comp_hosts and ip:
            sn = _subnet(ip)
            if sn and sn in comp_subnets:
                at_risk["hosts"].add(host)
                at_risk_rationale.setdefault(
                    f"hosts||{host}",
                    f"Co-located on subnet '{sn}' with a compromised host",
                )

    # Trust expansion: hosts accessed by the same user who accessed a
    # compromised host (shared administration trust).
    user_comp_hosts: Dict[str, Set[str]] = {}
    for ev in incident_events:
        if ev.user:
            user_comp_hosts.setdefault(ev.user, set()).add(ev.destination_host or ev.source_host)
    for ev in events:
        if ev.user in user_comp_hosts and ev.destination_host:
            host = ev.destination_host
            if host not in comp_hosts and host not in at_risk["hosts"]:
                at_risk["hosts"].add(host)
                at_risk_rationale.setdefault(
                    f"hosts||{host}",
                    f"Accessed by '{ev.user}', who also accessed a compromised host",
                )

    # ---------- Helper asset lists with evidence ---------------------------
    def _assets(kind: str, labels: Set[str]) -> List[Dict]:
        out = []
        for label in sorted(labels):
            item: Dict = {
                "type": kind,
                "id": f"{kind}||{label}",
                "label": label,
            }
            evid = compromised_evidence.get(f"{kind}||{label}")
            if evid:
                item["evidence"] = sorted(set(evid))
            item["status"] = "COMPROMISED"
            out.append(item)
        return out

    def _at_risk_assets(kind: str, labels: Set[str]) -> List[Dict]:
        out = []
        for label in sorted(labels):
            out.append({
                "type": kind,
                "id": f"{kind}||{label}",
                "label": label,
                "status": "AT_RISK",
                "rationale": at_risk_rationale.get(f"{kind}||{label}", "Reachable from a compromised asset"),
            })
        return out

    compromised_users = _assets("users", compromised["users"])
    compromised_ips = _assets("ips", compromised["ips"])
    compromised_hosts = _assets("hosts", compromised["hosts"])
    compromised_files = _assets("files", compromised["files"])

    at_risk_users = _at_risk_assets("users", at_risk["users"])
    at_risk_hosts = _at_risk_assets("hosts", at_risk["hosts"])
    at_risk_ips = _at_risk_assets("ips", at_risk["ips"])

    # ---------- FR-07.2: Data-flow correlation summary ---------------------
    data_flows: List[Dict] = []
    if graph:
        for e in graph.get("edges", []):
            if e.get("label") == "transferred to" and e.get("on_attack_path"):
                data_flows.append({
                    "source": _label_from_node_id(e.get("source", "")),
                    "target": _label_from_node_id(e.get("target", "")),
                    "evidence": e.get("evidence_event_ids", []),
                })

    # Aggregate (legacy) views for the UI / report layers.
    users_union = sorted(compromised["users"] | at_risk["users"])
    hosts_union = sorted(compromised["hosts"] | at_risk["hosts"])
    ips_union = sorted(compromised["ips"] | at_risk["ips"])
    files_union = sorted(compromised["files"])

    total_affected = (
        len(users_union) + len(ips_union) + len(hosts_union) + len(files_union)
    )

    compromised_manifest = {
        "users": [u["label"] for u in compromised_users],
        "ips": [ip["label"] for ip in compromised_ips],
        "hosts": [h["label"] for h in compromised_hosts],
        "files": [f["label"] for f in compromised_files],
        "assets": (
            compromised_users
            + compromised_ips
            + compromised_hosts
            + compromised_files
        ),
    }

    at_risk_manifest = {
        "users": [u["label"] for u in at_risk_users],
        "ips": [ip["label"] for ip in at_risk_ips],
        "hosts": [h["label"] for h in at_risk_hosts],
        "assets": (
            at_risk_users + at_risk_hosts + at_risk_ips
        ),
    }

    return {
        "compromised": compromised_manifest,
        "at_risk": at_risk_manifest,
        "data_flows": data_flows,
        "users": users_union,
        "ips": ips_union,
        "hosts": hosts_union,
        "files": files_union,
        "total_affected": total_affected,
        "entry_point": entry_point,
    }
