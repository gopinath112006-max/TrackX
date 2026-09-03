import hashlib
import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional


def sha256_file(file_bytes: bytes) -> str:
    """Compute the SHA-256 hash of a file's raw bytes for forensic integrity."""
    return hashlib.sha256(file_bytes).hexdigest()


def safe_json_dumps(obj: Any) -> str:
    """Serialize an object to JSON safely with a fallback for non-serializable values."""
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return json.dumps({"raw": str(obj)})


def safe_json_loads(text: Optional[str], default: Any = None) -> Any:
    """Parse JSON text safely, returning the default on any failure."""
    if not text:
        return default
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default


def sanitize_input(value: str, max_length: int = 1024) -> str:
    """Strip control characters and trim input to prevent injection/display issues."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    return value[:max_length]


#: Timezone offset regex: an ISO-style "Z", "+HH:MM", "+HHMM", "-HH:MM", ...
_TZ_RE = re.compile(
    r"(?:Z|[+-]\d{2}:?\d{2})?$"
)


def parse_timestamp(timestamp_str: str) -> Optional[str]:
    """
    Normalize a timestamp string into a canonical UTC ISO 8601 format with
    microsecond precision ('YYYY-MM-DDTHH:MM:SS.ffffffZ', FR-02.2).

    Supports:
      - ISO 8601 ('2024-01-01T12:00:00', with optional fractional seconds and
        'Z' or '+HH:MM' timezone offsets)
      - Space-separated datetime ('2024-01-01 12:00:00')
      - RFC 2822 ('Mon, 02 Jan 2006 15:04:05 -0700', email.utils)
      - UNIX epoch seconds / milliseconds / microseconds (numeric)
      - Syslog formats ('Jan  2 15:04:05 host cmd' and RFC 3164-style headers)

    All resolved timestamps are converted to UTC with microsecond precision.
    Returns None if it cannot be parsed. Never mutates the original string.
    """
    if timestamp_str is None:
        return None
    ts = str(timestamp_str).strip()
    if not ts:
        return None

    # --- Numeric epoch (seconds / milliseconds / microseconds) ---
    if _is_numeric(ts):
        return _from_epoch(ts)

    # --- Syslog-ish: "Mon DD HH:MM:SS" or "Mon DD HH:MM:SS YYYY" prefix ---
    syslog = _match_syslog(ts)
    if syslog is not None:
        return syslog

    # --- RFC 2822 (email.utils handles offsets robustly) ---
    try:
        parsed = parsedate_to_datetime(ts)
        if parsed is not None:
            return _to_utc_iso(parsed)
    except (TypeError, ValueError, OverflowError):
        pass

    # --- ISO 8601 / space-separated datetime ---
    iso = _match_iso(ts)
    if iso is not None:
        return iso

    # --- Date-only 'YYYY-MM-DD' ---
    m2 = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", ts)
    if m2:
        return "{}-{}-{}T00:00:00.000000Z".format(*m2.groups())

    return None


def _is_numeric(value: str) -> bool:
    """True if the trimmed string is entirely digits (with optional '-')."""
    if not value:
        return False
    return value.lstrip("-").isdigit()


def _from_epoch(value: str) -> Optional[str]:
    """Convert a numeric epoch (s/ms/us) into a UTC ISO 8601 string."""
    try:
        num = int(value)
    except (TypeError, ValueError):
        return None
    # Heuristics: 13 digits -> ms, 16 -> us, else seconds.
    if abs(num) >= 1_000_000_000_000_000:  # 16 digits -> microseconds
        return _to_utc_iso(datetime.fromtimestamp(num / 1_000_000, tz=timezone.utc))
    if abs(num) >= 1_000_000_000_000:  # 13 digits -> milliseconds
        return _to_utc_iso(datetime.fromtimestamp(num / 1000, tz=timezone.utc))
    # Otherwise treat as seconds (10 digits). Sub-second precision is lost for
    # float seconds, which is acceptable for standard epoch timestamps.
    return _to_utc_iso(datetime.fromtimestamp(num, tz=timezone.utc))


def _match_syslog(value: str) -> Optional[str]:
    """Match Syslog RFC 3164 / common "Mon DD HH:MM:SS" prefixes."""
    # e.g. "Jan  2 15:04:05 host cmd..." or "Jan 2 15:04:05 2023 ..."
    m = re.match(
        r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
        r"(?P<t>\d{2}:\d{2}:\d{2})(?:\s+(?P<year>\d{4}))?",
        value,
    )
    if not m:
        return None
    month_map = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
        "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    }
    month = month_map.get(m.group("mon").lower())
    if month is None:
        return None
    year = int(m.group("year")) if m.group("year") else datetime.now().year
    day = int(m.group("day"))
    try:
        dt = datetime(year, month, day, *[int(x) for x in m.group("t").split(":")])
    except ValueError:
        return None
    # Syslog timestamps carry no zone; assume local time is UTC-agnostic, but
    # to keep determinism we treat them as UTC by default per FR-02.2.
    return _to_utc_iso(dt.replace(tzinfo=timezone.utc))


def _match_iso(value: str) -> Optional[str]:
    """Match ISO 8601 / space-separated datetimes with optional timezone."""
    # Capture date, optional time, optional fractional seconds, optional zone.
    m = re.match(
        r"(?P<dt>\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2})?)"
        r"(?P<frac>\.\d+)?"
        r"(?P<zone>Z|[+-]\d{2}:?\d{2})?",
        value,
    )
    if not m:
        return None
    dt_str = m.group("dt")
    try:
        dt = datetime.fromisoformat(dt_str)
    except ValueError:
        return None
    frac = m.group("frac")
    zone = m.group("zone")

    if zone:
        dt = _apply_zone(dt, zone)
    elif dt.tzinfo is None:
        # Naive input: assume UTC baseline per FR-02.2 (no assumed local time).
        dt = dt.replace(tzinfo=timezone.utc)

    # Preserve microsecond precision from an explicit fractional part.
    if frac and len(frac) > 1:
        digits = frac[1:]
        digits = (digits + "000000")[:6]
        micros = int(digits)
        dt = dt.replace(microsecond=micros)

    return _to_utc_iso(dt)


def _apply_zone(dt: datetime, zone: str) -> datetime:
    """Attach a timezone offset to a naive datetime."""
    if zone in ("Z", "z"):
        return dt.replace(tzinfo=timezone.utc)
    sign = 1 if zone[0] == "+" else -1
    body = zone[1:].replace(":", "")
    hours = int(body[:2])
    minutes = int(body[2:4]) if len(body) >= 4 else 0
    import datetime as _dt
    offset = _dt.timedelta(hours=hours, minutes=minutes)
    try:
        tz = _dt.timezone(sign * offset)
        return dt.replace(tzinfo=tz)
    except (ValueError, OverflowError):
        return dt.replace(tzinfo=timezone.utc)


def _to_utc_iso(dt: datetime) -> str:
    """Convert a datetime to a UTC ISO 8601 string with microsecond precision."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def parse_datetime_naive(ts_str: str) -> Optional[datetime]:
    """
    Parse a normalized canonical timestamp (usually produced by
    `parse_timestamp`) into a *naive* UTC datetime for safe chronological
    comparison and sorting.

    Analysis modules must compare timestamps regardless of whether the input
    string carried an explicit zone offset. This helper converts to UTC and
    strips the tzinfo so the result is consistently comparable to naive
    datetimes (e.g. `datetime.min`). Returns None on parse failure.
    """
    parsed = parse_timestamp(ts_str)
    if parsed is None:
        return None
    try:
        dt = datetime.fromisoformat(parsed)
    except ValueError:
        return None
    # `parse_timestamp` always yields a UTC ('Z') string, so it is aware.
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt
