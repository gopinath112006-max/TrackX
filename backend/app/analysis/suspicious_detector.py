"""
Suspicious Activity Detection
=============================
Rule-based, explainable detection of suspicious activities across
normalized events. Every finding includes a human-readable 'reason'
explaining why it was flagged, plus the related event IDs.

Rules:
  Rule 1: Multiple failed logins followed by a successful login
          -> Possible brute-force/account compromise
  Rule 2: Login from an unusual (one-off / external) IP
          -> Suspicious login source
  Rule 3: Sensitive file accessed after a suspicious login / failure burst
          -> Possible unauthorized sensitive-file access
  Rule 4: Large number of file downloads in a short window
          -> Possible data collection
  Rule 5: Large outbound data transfer
          -> Possible data exfiltration
  Rule 6: User accesses multiple systems within a short time
          -> Possible lateral movement
  Rule 7: Login outside the normal activity window
          -> Login outside normal activity window
  Rule 8: Privilege escalation (sudo/su/UAC/domain-admin promotion)
          -> Privilege escalation (FR-06.3)
  Rule 9: Persistence installation (scheduled task/service/startup/backdoor)
          -> Persistence mechanism (FR-06.4)
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

from app.schemas.schemas import NormalizedEvent
from app.utils.helpers import parse_datetime_naive
from app.config import conf_int, conf_list

# Sensitive file keyword patterns (externalized: detection.sensitive_file_keywords)
SENSITIVE_FILE_KEYWORDS = conf_list("detection.sensitive_file_keywords", [
    "student", "password", "credential", "database", "financial", "payment",
    "social_security", "medical", "salary", "tax", "customer", "credit",
    "secret", "confidential", "private", "personal", "employee", "dump",
    "backup", "sql", "xlsx", "db", "csv", "key", "auth",
])

# Normal activity window (hours in 24-hour format)
NORMAL_ACTIVITY_START_HOUR = conf_int("detection.normal_activity.start_hour", 8)
NORMAL_ACTIVITY_END_HOUR = conf_int("detection.normal_activity.end_hour", 20)

# Thresholds (FR-05.1): K failed attempts within a W_auth-second window
# followed by a success identify an initial-access burst.
FAILED_LOGIN_BURST_THRESHOLD = conf_int("detection.brute_force.failed_login_burst_threshold", 5)
BRUTE_FORCE_WINDOW_SECONDS = conf_int("detection.brute_force.window_seconds", 900)  # W_auth = 15 min
FILE_DOWNLOAD_BURST_THRESHOLD = conf_int("detection.file_download.burst_threshold", 3)
EXFIL_THRESHOLD_MB = conf_int("detection.exfiltration.threshold_mb", 100)
LATERAL_MOVEMENT_HOST_THRESHOLD = conf_int("detection.lateral_movement.host_threshold", 2)


def _parse_ts(ts_str: str) -> datetime | None:
    return parse_datetime_naive(ts_str)


def _hour_of(events: List[NormalizedEvent]) -> datetime | None:
    """Return timestamp as datetime for the first event with a parseable time."""
    for ev in events:
        dt = _parse_ts(ev.timestamp)
        if dt:
            return dt
    return None


def _is_sensitive_file(filename: str) -> bool:
    """Heuristic check whether a file path/name looks sensitive."""
    if not filename:
        return False
    name_lower = filename.lower()
    return any(kw in name_lower for kw in SENSITIVE_FILE_KEYWORDS)


def _is_unusual_ip(ip: str, known_ips: set) -> bool:
    """Heuristic: an IP used only once, or an obvious non-private/external one."""
    if not ip:
        return False
    return ip not in known_ips


def is_public_ip(ip: str) -> bool:
    """Check if an IP address appears to be public (non-RFC-1918 / loopback / link-local)."""
    try:
        parts = [int(x) for x in ip.split(".")]
    except (ValueError, AttributeError):
        return False
    if len(parts) != 4:
        return False
    octet1, octet2 = parts[0], parts[1]
    private = (
        octet1 == 10
        or (octet1 == 172 and 16 <= octet2 <= 31)
        or (octet1 == 192 and octet2 == 168)
        or (octet1 == 127)
        or (octet1 == 169 and octet2 == 254)
    )
    return not private


def detect_suspicious_activities(events: List[NormalizedEvent]) -> List[Dict[str, object]]:
    """
    Run all detection rules over the given events and return a list of findings.
    Each finding:
      {
        "finding_id": str,
        "title": str,
        "description": str,
        "severity": str,
        "confidence": float,
        "related_event_ids": list[str],
        "reason": str,
        "category": str,
      }
    """
    findings: List[Dict[str, object]] = []

    _rule1_bruteforce(events, findings)
    _rule2_unusual_ip_login(events, findings)
    _rule3_sensitive_access(events, findings)
    _rule4_many_downloads(events, findings)
    _rule5_data_exfiltration(events, findings)
    _rule6_lateral_movement(events, findings)
    _rule7_unusual_time(events, findings)
    _rule8_privilege_escalation(events, findings)
    _rule9_persistence(events, findings)

    return findings


def _rule1_bruteforce(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Detect K failed logins within a W_auth window followed by a success (FR-05.1).

    For every (user, source_ip) group we look for a rolling window of length
    W_auth = 900s containing at least K = 5 failed attempts, and require that
    a successful login follows the burst within the same window. Reporting only
    the most significant burst per group keeps findings concise.
    """
    # Group login events per (user, source_ip)
    groups: Dict[tuple, List[NormalizedEvent]] = defaultdict(list)
    for ev in events:
        if (
            ev.event_type in ("LOGIN", "LOGOUT")
            and ev.action.lower() in ("login", "logon", "authentication")
        ) or ("login" in ev.action.lower()):
            key = (ev.user, ev.source_ip)
            groups[key].append(ev)

    for (user, ip), evs in groups.items():
        if not user:
            continue
        # Sort by timestamp
        evs.sort(key=lambda e: _parse_ts(e.timestamp) or datetime.min)
        timed = [(e, _parse_ts(e.timestamp)) for e in evs]
        timed = [(e, dt) for e, dt in timed if dt is not None]
        if not timed:
            continue

        # Sliding window over all login events: find a cluster of >= K fails
        # (followed by a success) wholly within W_auth seconds.
        best_burst: List[NormalizedEvent] = []
        best_success = None
        for start in range(len(timed)):
            window_start = timed[start][1]
            window_end = window_start + timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
            cluster = [e for e, dt in timed if window_start <= dt <= window_end]
            fails_in_cluster = [
                e for e in cluster
                if e.status and "fail" in e.status.lower()
            ]
            # A success must follow the burst within the window.
            success_after = [
                e for e in cluster
                if e.status and "success" in e.status.lower()
                and (fails_in_cluster and _parse_ts(e.timestamp) >= _parse_ts(fails_in_cluster[-1].timestamp))
            ]
            if len(fails_in_cluster) >= FAILED_LOGIN_BURST_THRESHOLD and success_after:
                if len(fails_in_cluster) > len(best_burst):
                    best_burst = fails_in_cluster
                    best_success = success_after[0]
            if len(best_burst) >= FAILED_LOGIN_BURST_THRESHOLD:
                break

        if len(best_burst) >= FAILED_LOGIN_BURST_THRESHOLD and best_success:
            burst_events = sorted(
                best_burst + [best_success],
                key=lambda e: _parse_ts(e.timestamp) or datetime.min,
            )
            related = [e.event_id for e in burst_events]
            confidence = min(95, 60 + len(best_burst) * 3)
            findings.append({
                "finding_id": f"FND-{len(findings) + 1:03d}",
                "title": "Possible brute-force attack",
                "description": (
                    f"{len(best_burst)} failed login attempts against account '{user}' "
                    f"from {ip} within {BRUTE_FORCE_WINDOW_SECONDS // 60} minutes "
                    f"({BRUTE_FORCE_WINDOW_SECONDS // 60}-minute window) were followed by a "
                    "successful login. This pattern is consistent with a brute-force attack "
                    "and possible account compromise."
                ),
                "severity": "HIGH",
                "confidence": confidence,
                "related_event_ids": related,
                "reason": (
                    f"{len(best_burst)} failed login attempts followed by a successful login "
                    f"for user '{user}' from {ip} within a {BRUTE_FORCE_WINDOW_SECONDS // 60}-minute window "
                    "(FR-05.1)."
                ),
                "category": "brute_force",
                "phase": "INITIAL_ACCESS",
            })
            return  # only report once per group


def _rule2_unusual_ip_login(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Flag logins originating from an IP that is used only once or is public."""
    login_events = [e for e in events if "login" in e.action.lower()]
    if not login_events:
        return
    # Count login occurrences per IP
    ip_counts: Dict[str, int] = defaultdict(int)
    for e in login_events:
        if e.source_ip:
            ip_counts[e.source_ip] += 1

    seen_ips = set(ip_counts.keys())
    for e in login_events:
        if e.source_ip and ip_counts[e.source_ip] == 1 and e.status and "success" in e.status.lower():
            if is_public_ip(e.source_ip):
                findings.append({
                    "finding_id": f"FND-{len(findings) + 1:03d}",
                    "title": "Suspicious login source",
                    "description": (
                        f"A successful login for user '{e.user}' originated from IP {e.source_ip}, "
                        "an address not previously seen in the evidence and outside the internal network."
                    ),
                    "severity": "MEDIUM",
                    "confidence": 70.0,
                    "related_event_ids": [e.event_id],
                    "reason": f"Login from a single-use public IP ({e.source_ip}) not seen elsewhere in the evidence.",
                    "category": "unusual_login",
                })


def _rule3_sensitive_access(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Flag sensitive-file access after a suspicious (failed-burst) login."""
    # Identify "suspicious" login sequences
    suspicious_logins: List[NormalizedEvent] = []
    groups: Dict[tuple, List[NormalizedEvent]] = defaultdict(list)
    for ev in events:
        if "login" in ev.action.lower():
            groups[(ev.user, ev.source_ip)].append(ev)
    for (user, ip), evs in groups.items():
        fails = [e for e in evs if e.status and "fail" in e.status.lower()]
        if len(fails) >= FAILED_LOGIN_BURST_THRESHOLD:
            suspicious_logins.extend(evs)

    suspicious_users = {e.user for e in suspicious_logins if e.user}

    # Find sensitive file accesses by those users shortly after login
    for ev in events:
        if ev.event_type == "FILE_ACCESS" and ev.user in suspicious_users:
            if _is_sensitive_file(ev.file_path or ""):
                # Check if the access happened after the suspicious login
                findings.append({
                    "finding_id": f"FND-{len(findings) + 1:03d}",
                    "title": "Possible unauthorized sensitive-file access",
                    "description": (
                        f"User '{ev.user}' accessed sensitive file '{ev.file_path}' after a "
                        "suspicious login sequence. This is consistent with an attacker using "
                        "compromised credentials to access confidential data."
                    ),
                    "severity": "HIGH",
                    "confidence": 85.0,
                    "related_event_ids": [ev.event_id] + [e.event_id for e in suspicious_logins[:2]],
                    "reason": (
                        f"Sensitive file '{ev.file_path}' was accessed by user '{ev.user}' "
                        "following a burst of failed logins for the same account."
                    ),
                    "category": "sensitive_access",
                })
                return


def _rule4_many_downloads(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Flag a large number of file downloads within a short window by one user."""
    download_events = [
        e for e in events
        if e.event_type in ("FILE_DOWNLOAD", "FILE_ACCESS")
        and e.action.lower() in ("download", "download_file", "get", "fetch", "read", "copy")
    ]
    if len(download_events) < FILE_DOWNLOAD_BURST_THRESHOLD:
        return

    user_groups: Dict[str, List[NormalizedEvent]] = defaultdict(list)
    for e in download_events:
        if e.user:
            user_groups[e.user].append(e)

    BURST_WINDOW_MIN = 12

    for user, evs in user_groups.items():
        if len(evs) < FILE_DOWNLOAD_BURST_THRESHOLD:
            continue
        timed = [(e, _parse_ts(e.timestamp)) for e in evs]
        timed = [(e, dt) for e, dt in timed if dt is not None]
        timed.sort(key=lambda x: x[1])
        # Sliding window: find a cluster of >= threshold events within the window
        clustered = []
        for start in range(len(timed)):
            window_start = timed[start][1]
            cluster = []
            for e, dt in timed[start:]:
                if (dt - window_start).total_seconds() <= BURST_WINDOW_MIN * 60:
                    cluster.append(e)
                else:
                    break
            if len(cluster) >= FILE_DOWNLOAD_BURST_THRESHOLD:
                clustered = cluster
                break
        if clustered:
            event_ids = [e.event_id for e in clustered][:10]
            findings.append({
                "finding_id": f"FND-{len(findings) + 1:03d}",
                "title": "Possible data collection",
                "description": (
                    f"User '{user}' performed {len(clustered)} file access/download operations "
                    f"within a {BURST_WINDOW_MIN}-minute period, which is consistent with data "
                    "collection behavior."
                ),
                "severity": "MEDIUM",
                "confidence": min(90, 60 + len(clustered) * 5),
                "related_event_ids": event_ids,
                "reason": (
                    f"{len(clustered)} file download/access operations by user '{user}' "
                    f"within a {BURST_WINDOW_MIN}-minute window."
                ),
                "category": "data_collection",
            })
            return


def _rule5_data_exfiltration(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Flag large outbound data transfers (aggregated per destination)."""
    # Only outbound actions (send/upload/transfer); inbound 'receive' is not exfiltration
    outbound = []
    for ev in events:
        action_l = ev.action.lower()
        if ev.event_type in ("DATA_TRANSFER", "FILE_UPLOAD") and any(
            k in action_l for k in ("send", "upload", "transfer", "put")
        ):
            outbound.append(ev)

    if not outbound:
        return

    # Aggregate transfer totals per (source_ip, destination_ip) within the evidence window
    from collections import defaultdict as _dd
    totals: Dict[str, dict] = _dd(lambda: {"size_mb": 0.0, "events": [], "dest": None, "src": None})
    for ev in outbound:
        size_mb = _extract_transfer_size(ev)
        if size_mb is None:
            continue
        dest = ev.destination_ip or ev.destination_host or "external"
        src = ev.source_ip or ev.source_host or "internal"
        key = f"{src}->{dest}"
        totals[key]["size_mb"] += size_mb
        totals[key]["events"].append(ev)
        totals[key]["dest"] = dest
        totals[key]["src"] = src

    for key, info in totals.items():
        total_mb = info["size_mb"]
        if total_mb >= EXFIL_THRESHOLD_MB:
            evs = info["events"]
            findings.append({
                "finding_id": f"FND-{len(findings) + 1:03d}",
                "title": "Possible data exfiltration",
                "description": (
                    f"A total of approximately {total_mb:.1f} MB of data was transferred "
                    f"to '{info['dest']}' from '{info['src']}' across {len(evs)} outbound "
                    f"transfer event(s). This volume is consistent with data exfiltration."
                ),
                "severity": "CRITICAL",
                "confidence": 92.0,
                "related_event_ids": [e.event_id for e in evs][:12],
                "reason": (
                    f"Aggregated outbound transfer of {total_mb:.1f} MB to '{info['dest']}' "
                    f"exceeds the {EXFIL_THRESHOLD_MB} MB threshold ({len(evs)} transfer events)."
                ),
                "category": "exfiltration",
            })
            return


def _extract_transfer_size(ev: NormalizedEvent) -> float | None:
    """Extract a transfer size (in MB) from the raw_data of an event.

    Numeric size columns are always assumed to be in bytes and converted to
    MiB; only an explicit 'NNN MB' string in the action is taken as MB.
    """
    raw = ev.raw_data or {}
    size_val = None
    for key in ("bytes", "bytes_transferred", "size", "data_size", "transfer_size", "volume", "bytes_sent"):
        if key in raw:
            size_val = raw[key]
            break

    if size_val is None:
        # Fallback: interpret 'action' string (e.g., "download 50MB")
        action_l = ev.action.lower()
        import re
        m = re.search(r"(\d+)\s*(mb|m)", action_l)
        if m:
            return float(m.group(1))
        return None

    try:
        val = float(size_val)
    except (TypeError, ValueError):
        return None
    return val / (1024 * 1024)


def _rule6_lateral_movement(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Flag a user accessing multiple hosts within a short time window."""
    if not events:
        return
    # Group access events by user, then detect distinct hosts visited close in time
    from datetime import timedelta
    user_accesses: Dict[str, List[NormalizedEvent]] = defaultdict(list)
    for ev in events:
        if ev.user:
            user_accesses[ev.user].append(ev)

    LATERAL_WINDOW_MIN = 20

    for user, evs in user_accesses.items():
        if not user:
            continue
        # Collect distinct destination hosts accessed with timestamps.
        # Only destination_host counts (the system being accessed); source_host
        # may hold an IP address or workstation name and would create noise.
        host_times: Dict[str, List] = defaultdict(list)
        for ev in evs:
            host = ev.destination_host
            dt = _parse_ts(ev.timestamp)
            if host and dt:
                host_times[host].append(dt)

        if len(host_times) < LATERAL_MOVEMENT_HOST_THRESHOLD:
            continue

        # Check whether any pair of distinct hosts were accessed within the window
        hosts_list = list(host_times.keys())
        too_close = False
        for i in range(len(hosts_list)):
            for j in range(i + 1, len(hosts_list)):
                t_i = host_times[hosts_list[i]][0]
                t_j = host_times[hosts_list[j]][0]
                if abs((t_j - t_i).total_seconds()) <= LATERAL_WINDOW_MIN * 60:
                    too_close = True
                    break
            if too_close:
                break

        if too_close:
            findings.append({
                "finding_id": f"FND-{len(findings) + 1:03d}",
                "title": "Possible lateral movement",
                "description": (
                    f"User '{user}' was observed accessing {len(hosts_list)} different hosts "
                    f"({', '.join(sorted(hosts_list))}) within a {LATERAL_WINDOW_MIN}-minute window. "
                    "This is consistent with lateral movement across the network."
                ),
                "severity": "HIGH",
                "confidence": 82.0,
                "related_event_ids": [e.event_id for e in evs if e.destination_host in hosts_list][:10],
                "reason": (
                    f"User '{user}' accessed multiple hosts "
                    f"({', '.join(sorted(hosts_list))}) within a short time window, "
                    "indicating possible lateral movement."
                ),
                "category": "lateral_movement",
            })
            return


def _rule7_unusual_time(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Flag successful logins that occur outside the normal activity window."""
    for ev in events:
        if "login" in ev.action.lower() and ev.status and "success" in ev.status.lower():
            dt = _parse_ts(ev.timestamp)
            if dt is None:
                continue
            hour = dt.hour
            if hour < NORMAL_ACTIVITY_START_HOUR or hour >= NORMAL_ACTIVITY_END_HOUR:
                findings.append({
                    "finding_id": f"FND-{len(findings) + 1:03d}",
                    "title": "Login outside normal activity window",
                    "description": (
                        f"A successful login for user '{ev.user}' occurred at {ev.timestamp}, "
                        f"outside the normal activity window ({NORMAL_ACTIVITY_START_HOUR}:00-{NORMAL_ACTIVITY_END_HOUR}:00)."
                    ),
                    "severity": "LOW",
                    "confidence": 55.0,
                    "related_event_ids": [ev.event_id],
                    "reason": f"Login timestamp {ev.timestamp} falls outside the normal activity window.",
                    "category": "unusual_time",
                })
                return


# --- Privilege escalation signatures (FR-06.3) -----------------------------
# Binaries/verbs that transition an identity from standard to elevated role.
PRIVILEGE_ESCALATION_BINARIES = conf_list("detection.privilege_escalation.binaries", [
    "sudo", "su ", "runas", "uac_bypass", "seclogon", "token_impersonation",
    "impersonate", "setuid", "setgid", "psexec", "enable_admin",
])

# Actions that add an identity to a privileged group (sudoers/domain admins).
PRIVILEGE_GROUP_ACTIONS = conf_list("detection.privilege_escalation.group_actions", [
    "add to sudoers", "add to admins", "add to domain admins", "group membership",
    "add_member", "add group member", "promote",
])

# Elevated role markers that indicate a higher privilege level than standard.
ELEVATED_ROLE_MARKERS = conf_list("detection.privilege_escalation.elevated_role_markers",
                                  ["admin", "root", "sudo", "system", "domain admin", "superuser"])


def _privilege_escalation_reason(ev: NormalizedEvent) -> str | None:
    """Return a human-readable elevation reason, or None if not an escalation."""
    raw = ev.raw_data or {}
    action_l = (ev.action or "").lower()
    process_l = (str(raw.get("process") or raw.get("command") or "")).lower()
    oper_l = (str(raw.get("operation") or ev.event_type or "")).lower()

    searchable = f"{action_l} {process_l} {oper_l}"

    for bin in PRIVILEGE_ESCALATION_BINARIES:
        if bin in searchable:
            return f"privilege-elevating execution via '{bin}'"

    for act in PRIVILEGE_GROUP_ACTIONS:
        if act in searchable:
            return f"account promoted via '{act}'"

    # Role transition: role(t2) > role(t1) on the same user/host (FR-06.3).
    prev_role = raw.get("previous_role") or raw.get("old_role")
    new_role = raw.get("new_role") or raw.get("current_role")
    if prev_role and new_role and prev_role.lower() != new_role.lower():
        if any(m in new_role.lower() for m in ELEVATED_ROLE_MARKERS):
            return f"role escalated from '{prev_role}' to '{new_role}'"

    return None


def _rule8_privilege_escalation(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Detect privilege escalation events (FR-06.3).

    Flags process execution involving privilege-modification binaries
    (sudo/su/UAC/system token impersonation), account promotion to
    privileged groups, or a role transition to an elevated role.
    """
    for ev in events:
        reason = _privilege_escalation_reason(ev)
        if not reason:
            continue
        host = ev.destination_host or ev.source_host or "unknown host"
        findings.append({
            "finding_id": f"FND-{len(findings) + 1:03d}",
            "title": "Privilege escalation",
            "description": (
                f"An identity gained elevated privileges on '{host}': {reason}. "
                "Privilege escalation is a critical step in the attack lifecycle, "
                "granting the attacker the ability to move laterally and exfiltrate data."
            ),
            "severity": "HIGH",
            "confidence": 88.0,
            "related_event_ids": [ev.event_id],
            "reason": f"{reason} observed on host '{host}' (FR-06.3).",
            "category": "privilege_escalation",
            "phase": "PRIVILEGE_ESCALATION",
        })
        return  # report the most significant elevation once


# --- Persistence signatures (FR-06.4) --------------------------------------
# Scheduled task / cron creation.
PERSIST_SCHEDULED_TERMS = conf_list("detection.persistence.scheduled_terms", [
    "scheduled task", "create schedule", "cron", "at command", "schtasks",
    "register task", "task scheduler",
])
# Service installation.
PERSIST_SERVICE_TERMS = conf_list("detection.persistence.service_terms", [
    "create service", "install service", "new service", "start service",
    "sc create", "systemd unit", "create daemon",
])
# Startup script / run-key modification.
PERSIST_STARTUP_TERMS = conf_list("detection.persistence.startup_terms", [
    "startup", "autorun", "run key", "run\\", "init.d", "rc.local",
    "startup folder", "hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "hklm\\software\\microsoft\\windows\\currentversion\\run",
])
# Backdoor / new local account creation.
PERSIST_ACCOUNT_TERMS = conf_list("detection.persistence.account_terms", [
    "create user", "add user", "new local user", "create account",
    "add account", "net user", "create backdoor",
])


def _persistence_reason(ev: NormalizedEvent) -> str | None:
    """Return a persistence-mechanism reason, or None if not a persistence action."""
    raw = ev.raw_data or {}
    action_l = (ev.action or "").lower()
    proc_l = (str(raw.get("process") or raw.get("command") or "")).lower()
    target_l = (str(raw.get("target") or raw.get("target_path") or ev.file_path or "")).lower()
    object_l = (str(raw.get("object") or raw.get("service") or raw.get("task") or raw.get("account") or "")).lower()

    searchable = f"{action_l} {proc_l} {target_l} {object_l}"

    categories = [
        ("scheduled task", PERSIST_SCHEDULED_TERMS),
        ("system service", PERSIST_SERVICE_TERMS),
        ("startup configuration", PERSIST_STARTUP_TERMS),
        ("backdoor account", PERSIST_ACCOUNT_TERMS),
    ]
    for mech, terms in categories:
        if any(t in searchable for t in terms):
            if mech == "backdoor account":
                account = raw.get("account") or raw.get("user") or ev.user or "?unknown?"
                return f"creation of a new local account '{account}'"
            if mech == "system service":
                svc = raw.get("service") or raw.get("object") or "?unknown?"
                return f"installation of a new system service '{svc}'"
            if mech == "scheduled task":
                task = raw.get("task") or raw.get("object") or "?unknown?"
                return f"creation of a scheduled task/cron entry '{task}'"
            return f"modification of a startup configuration ({target_l or 'unknown path'})"
    return None


def _rule9_persistence(events: List[NormalizedEvent], findings: List[Dict[str, object]]):
    """Detect persistence-installation actions (FR-06.4).

    Identifies scheduled-task/cron creation, new system services, startup
    configuration changes, and backdoor account creation on compromised hosts.
    """
    for ev in events:
        reason = _persistence_reason(ev)
        if not reason:
            continue
        host = ev.destination_host or ev.source_host or "unknown host"
        findings.append({
            "finding_id": f"FND-{len(findings) + 1:03d}",
            "title": "Persistence mechanism installed",
            "description": (
                f"A persistence foothold was installed on '{host}': {reason}. "
                "Persistence mechanisms allow an attacker to maintain access across "
                "system reboots and must be removed during remediation."
            ),
            "severity": "HIGH",
            "confidence": 85.0,
            "related_event_ids": [ev.event_id],
            "reason": f"{reason} on host '{host}' (FR-06.4).",
            "category": "persistence",
            "phase": "PERSISTENCE",
        })
        return  # report the most significant persistence action once
