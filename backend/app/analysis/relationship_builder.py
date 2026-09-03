"""
Relationship Graph Builder
==========================
Builds an entity-relationship graph from normalized events using NetworkX
(FR-03.3), then runs a forward-in-time Breadth-First Search (FR-06.1)
starting from the Initial Entry Point to trace the attack path.

Node types: USER, IP, HOST, FILE, EVENT, SERVER
Edge labels: "logged into", "accessed", "downloaded", "connected to",
             "transferred to", etc.

Beyond edges derived directly from event attributes, the builder runs a
link-inference pass that surfaces *hidden* relationships between seemingly
unrelated entities (e.g. two accounts sharing an IP, a file present on
multiple hosts, hosts linked through a common user). Inferred edges are
marked with `inferred: true` and a human-readable reason, and every edge
carries the aggregated evidence event IDs that support it.

The returned graph mirrors the working NetworkX digraph, so nodes/edges
reachable from the Initial Entry Point (the forward attack path) are tagged
with `on_attack_path: true`.
"""

import networkx as nx
from collections import defaultdict
from typing import Dict, List, Optional, Set

from app.utils.helpers import parse_datetime_naive
from app.config import conf_int

MAX_INFERRED_EDGES = conf_int("relationships.max_inferred_edges", 40)

# Forward-time bounding window for the BFS attack-path trace (FR-06.1).
ATTACK_PATH_TIME_WINDOW_SECONDS = conf_int("relationships.attack_path_time_window_seconds", 72 * 3600)


def _node_id(prefix: str, label: str) -> str:
    """Generate a stable, unique node id from a type prefix and label."""
    return f"{prefix}||{label}"


def _node_color(node_type: str) -> str:
    colors = {
        "USER": "#3b82f6",
        "IP": "#f59e0b",
        "HOST": "#10b981",
        "FILE": "#8b5cf6",
        "EVENT": "#94a3b8",
        "SERVER": "#ef4444",
    }
    return colors.get(node_type, "#64748b")


def build_relationship_graph(
    events: List[Dict],
    relationships_from_db: List[Dict] | None = None,
    entry_point_event_id: str | None = None,
) -> Dict[str, List[Dict]]:
    """
    Build the graph from events using a NetworkX directed property graph.

    Args:
        events: list of event dicts (must include event_id, user, source_ip, etc.)
        relationships_from_db: optional precomputed relationship rows.
        entry_point_event_id: optional event_id of the Initial Entry Point.
            When provided, a forward-in-time BFS is run from the entry point's
            entities to tag the attack path (FR-06.1).

    Returns:
        {"nodes": [...], "edges": [...]}
    """
    nodes: Dict[str, Dict] = {}
    edges: Dict[str, Dict] = {}
    edge_counter = [0]

    # Working NetworkX digraph used for topological traversal (FR-03.3).
    G = nx.DiGraph()

    def add_node(prefix: str, label: str, data: Dict | None = None):
        if not label:
            return None
        key = _node_id(prefix, label)
        if key not in nodes:
            nodes[key] = {
                "id": key,
                "type": prefix,
                "label": label,
                "color": _node_color(prefix),
                "data": data or {},
            }
            G.add_node(key, type=prefix, label=label)
        return key

    def add_edge(
        src: str, tgt: str, label: str, evidence_event_ids: List[str],
        inferred: bool = False, reason: str | None = None,
        ts_list: List[str] | None = None,
    ):
        """Add or merge an edge.

        Repeated calls for the same (src, label, tgt) merge their evidence
        event IDs, so edges aggregate every corroborating event instead of
        keeping only the first one. `inferred` edges are flagged so the UI
        can distinguish derived relationships from directly observed ones.
        """
        if not src or not tgt or src == tgt:
            return
        key = f"{src}|{label}|{tgt}"
        if key in edges:
            existing = edges[key]
            merged = list(dict.fromkeys((existing.get("evidence_event_ids") or []) + list(evidence_event_ids)))
            existing["evidence_event_ids"] = sorted(merged)
            return
        edge_counter[0] += 1
        edge = {
            "id": f"E{edge_counter[0]:03d}",
            "source": src,
            "target": tgt,
            "label": label,
            "evidence_event_ids": sorted(dict.fromkeys(evidence_event_ids)),
            "inferred": inferred,
        }
        if reason:
            edge["reason"] = reason
        if ts_list:
            edge["timestamps"] = sorted(ts_list)
        edges[key] = edge
        # Mirror into the NetworkX graph for BFS (single structural edge per
        # node pair; preserve the earliest timestamp on the edge).
        if G.has_edge(src, tgt):
            old_ts = G[src][tgt].get("_min_ts")
            ts_vals = ts_list or []
            if ts_vals:
                new_min = min(ts_vals)
                if old_ts is None or new_min < old_ts:
                    G[src][tgt]["_min_ts"] = new_min
        else:
            G.add_edge(src, tgt, label=label, inferred=inferred)
            ts_vals = ts_list or []
            if ts_vals:
                G[src][tgt]["_min_ts"] = min(ts_vals)

    for ev in events:
        eid = ev.get("event_id", "")
        user = ev.get("user")
        src_ip = ev.get("source_ip")
        dst_ip = ev.get("destination_ip")
        src_host = ev.get("source_host")
        dst_host = ev.get("destination_host")
        file_path = ev.get("file_path")
        event_type = ev.get("event_type", "")
        action = ev.get("action", "")
        ts = ev.get("timestamp", "")
        ts_list = [ts] if ts else None

        # Add relevant nodes
        user_node = add_node("USER", user) if user else None
        ip_node = add_node("IP", src_ip) if src_ip else None
        dst_ip_node = add_node("IP", dst_ip) if dst_ip else None
        src_host_node = add_node("HOST", src_host) if src_host else None
        dst_host_node = add_node("SERVER", dst_host) if dst_host else None
        file_node = add_node("FILE", file_path) if file_path else None

        # Login/logout
        if event_type in ("LOGIN", "LOGOUT"):
            if user_node and (dst_host_node or src_host_node or dst_ip_node):
                target = dst_host_node or src_host_node or dst_ip_node
                if "success" in (ev.get("status") or "").lower():
                    action_label = "logged into"
                else:
                    action_label = "failed to log into"
                add_edge(user_node, target, action_label, [eid], ts_list=ts_list)
            if ip_node and user_node:
                add_edge(ip_node, user_node, "logged in as", [eid], ts_list=ts_list)

        # File access
        elif event_type == "FILE_ACCESS":
            if user_node and file_node:
                add_edge(user_node, file_node, "accessed", [eid], ts_list=ts_list)
            if src_host_node and file_node:
                add_edge(src_host_node, file_node, "hosts", [eid], ts_list=ts_list)

        # File download
        elif event_type == "FILE_DOWNLOAD":
            if user_node and file_node:
                add_edge(user_node, file_node, "downloaded", [eid], ts_list=ts_list)
            if dst_ip_node and file_node:
                add_edge(dst_ip_node, file_node, "received", [eid], ts_list=ts_list)

        # File upload
        elif event_type == "FILE_UPLOAD":
            if user_node and file_node:
                add_edge(user_node, file_node, "uploaded", [eid], ts_list=ts_list)
            if ip_node and file_node:
                add_edge(ip_node, file_node, "sent", [eid], ts_list=ts_list)

        # Network connection / transfer
        elif event_type in ("NETWORK_CONNECTION", "DATA_TRANSFER"):
            if "transfer" in event_type.lower() or "transfer" in action.lower():
                label = "transferred to"
            else:
                label = "connected to"
            if ip_node and dst_ip_node:
                add_edge(ip_node, dst_ip_node, label, [eid], ts_list=ts_list)
            if src_host_node and dst_host_node:
                add_edge(src_host_node, dst_host_node, label, [eid], ts_list=ts_list)

        # Process/system activity
        elif event_type == "PROCESS_EXEC":
            if src_host_node and dst_host_node:
                add_edge(src_host_node, dst_host_node, "executed process", [eid], ts_list=ts_list)
            elif src_host_node and user_node:
                add_edge(src_host_node, user_node, "executed by", [eid], ts_list=ts_list)

    # --- Hidden relationship inference pass ---
    def already_connected(src: str, tgt: str) -> bool:
        prefix = f"{src}|"
        suffix = f"|{tgt}"
        return any(k.startswith(prefix) and k.endswith(suffix) for k in edges)

    inferred_count = [0]

    def infer_edge(src, tgt, label, evidence, reason):
        if inferred_count[0] >= MAX_INFERRED_EDGES:
            return
        if not src or not tgt or src == tgt:
            return
        if already_connected(src, tgt):
            return
        add_edge(src, tgt, label, evidence, inferred=True, reason=reason)
        inferred_count[0] += 1

    # 1. Two or more distinct accounts originating from the same source IP
    ip_users: Dict[str, Set[str]] = defaultdict(set)
    for ev in events:
        src_ip = ev.get("source_ip")
        user = ev.get("user")
        if src_ip and user:
            ip_users[src_ip].add(user)
    for src_ip, users in sorted(ip_users.items()):
        users_sorted = sorted(users)
        if len(users_sorted) < 2:
            continue
        ip_node = add_node("IP", src_ip)
        if not ip_node:
            continue
        for user in users_sorted:
            user_node = add_node("USER", user)
            if user_node:
                evidence = [
                    ev.get("event_id") for ev in events
                    if ev.get("source_ip") == src_ip and ev.get("user") == user
                ]
                infer_edge(
                    ip_node, user_node, "shared_ip", evidence,
                    f"IP {src_ip} is shared by {len(users_sorted)} account(s), "
                    f"suggesting a common origin or credential reuse",
                )

    # 2. A file observed on multiple hosts
    file_hosts: Dict[str, Set[str]] = defaultdict(set)
    for ev in events:
        fp = ev.get("file_path")
        if not fp:
            continue
        for h in (ev.get("destination_host"), ev.get("source_host")):
            if h:
                file_hosts[fp].add(h)
    for fp, hosts in sorted(file_hosts.items()):
        hosts_sorted = sorted(hosts)
        if len(hosts_sorted) < 2:
            continue
        for i in range(len(hosts_sorted)):
            for j in range(i + 1, len(hosts_sorted)):
                h1, h2 = hosts_sorted[i], hosts_sorted[j]
                node1 = add_node("HOST", h1)
                node2 = add_node("HOST", h2)
                if not node1 or not node2:
                    continue
                evidence = [
                    ev.get("event_id") for ev in events
                    if ev.get("file_path") == fp
                    and (ev.get("destination_host") or ev.get("source_host")) in (h1, h2)
                ]
                infer_edge(
                    node1, node2, "common_file", evidence,
                    f"Hosts '{h1}' and '{h2}' both reference file '{fp}'",
                )

    # 3. Hosts reached through a common user (possible lateral movement path)
    user_hosts: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    for ev in events:
        user = ev.get("user")
        host = ev.get("destination_host")
        if user and host:
            user_hosts[user][host].append(ev.get("event_id", ""))
    for user, host_evs in sorted(user_hosts.items()):
        hosts_sorted = sorted(host_evs.keys())
        if len(hosts_sorted) < 2:
            continue
        for i in range(len(hosts_sorted)):
            for j in range(i + 1, len(hosts_sorted)):
                h1, h2 = hosts_sorted[i], hosts_sorted[j]
                node1 = add_node("HOST", h1)
                node2 = add_node("HOST", h2)
                if not node1 or not node2:
                    continue
                evidence = sorted(set(host_evs[h1] + host_evs[h2]))
                infer_edge(
                    node1, node2, "related_via_user", evidence,
                    f"User '{user}' accessed both '{h1}' and '{h2}'",
                )

    # Include precomputed relationships (from database) if provided
    if relationships_from_db:
        for rel in relationships_from_db:
            src = add_node(rel.get("source_type", "HOST"), rel.get("source_node"))
            tgt = add_node(rel.get("target_type", "HOST"), rel.get("target_node"))
            if src and tgt:
                add_edge(src, tgt, rel.get("relationship_type", "related"), rel.get("evidence_event_ids", []))

    # --- Forward-in-time BFS attack-path trace (FR-06.1) ---
    if entry_point_event_id:
        _trace_attack_path(G, events, entry_point_event_id, nodes, edges)

    nodes_list = list(nodes.values())
    edges_list = list(edges.values())

    # Attach attack-path flags to the returned nodes/edges from the traced set.
    if entry_point_event_id:
        on_path_nodes = {
            n for n, d in G.nodes(data=True) if d.get("on_attack_path")
        }
        for n in nodes_list:
            n["on_attack_path"] = n["id"] in on_path_nodes
        for e in edges_list:
            e["on_attack_path"] = (
                e["source"] in on_path_nodes and e["target"] in on_path_nodes
                and G.has_edge(e["source"], e["target"])
                and G[e["source"]][e["target"]].get("on_attack_path", False)
            )

    return {"nodes": nodes_list, "edges": edges_list}


def _trace_attack_path(
    G: nx.DiGraph,
    events: List[Dict],
    entry_point_event_id: str,
    nodes: Dict[str, Dict],
    edges: Dict[str, Dict],
) -> None:
    """Run a forward-in-time BFS from the entry point and tag the subgraph.

    Identification (FR-06.1):
      1. Locate the entry-point event's entity nodes (user, source IP, host).
      2. BFS outward through directed edges, but only traverse an edge when
         the edge's earliest timestamp is within the forward bounding window
         `ATTACK_PATH_TIME_WINDOW_SECONDS` of the entry point.
      3. Tag all reached nodes/edges with `on_attack_path`.
    """
    entry_ev = next((ev for ev in events if ev.get("event_id") == entry_point_event_id), None)
    if not entry_ev:
        # Unknown entry point: fall back to the networkx BFS over all reachable
        # nodes from wherever the entry point ids to, if any node matches.
        return
    if not events:
        return

    root_ts = parse_datetime_naive(entry_ev.get("timestamp", ""))
    if root_ts is None:
        return

    # Determine the entry point's entity node ids.
    roots: List[str] = []
    candidates = [
        ("USER", entry_ev.get("user")),
        ("IP", entry_ev.get("source_ip")),
        ("IP", entry_ev.get("destination_ip")),
        ("HOST", entry_ev.get("source_host")),
        ("SERVER", entry_ev.get("destination_host")),
    ]
    for prefix, label in candidates:
        if label:
            key = _node_id(prefix, label)
            if G.has_node(key):
                roots.append(key)

    # BFS limited to forward-in-time edges.
    visited: Set[str] = set()
    from collections import deque
    queue = deque(roots)
    for r in roots:
        visited.add(r)

    while queue:
        cur = queue.popleft()
        for nxt in G.successors(cur):
            edge_data = G[cur][nxt]
            min_ts = edge_data.get("_min_ts")
            if min_ts is not None:
                edge_dt = parse_datetime_naive(min_ts)
                if edge_dt is not None:
                    if edge_dt < root_ts:
                        # Only forward-in-time traversal; backward links aren't
                        # part of the post-entry execution path.
                        continue
                    delta = (edge_dt - root_ts).total_seconds()
                    if delta > ATTACK_PATH_TIME_WINDOW_SECONDS:
                        continue
                G[cur][nxt]["on_attack_path"] = True
            else:
                G[cur][nxt]["on_attack_path"] = True
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)

    # Mark reached nodes.
    for n in visited:
        if G.has_node(n):
            G.nodes[n]["on_attack_path"] = True
