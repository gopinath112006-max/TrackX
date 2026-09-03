"""
Parallel Processing Utilities
=============================
Deterministic, order-preserving parallel map used to accelerate the
ingestion & normalization hot paths (NFR-P-02: >= 10k rows/sec).

Correctness contract:
  * Parallelism NEVER reorders results - `parallel_map` returns results in
    the exact same order as the input (via ThreadPoolExecutor.map).
  * Deterministic: the transformation applied to each item is a pure
    function of that item (and any precomputed inputs), so output is
    bit-identical whether or not parallelism is used (NFR-R-01).

To guarantee determinism, callers MUST precompute any sequential identifiers
(event_ids, line_index, raw_ref) before calling parallel_map - the mapped
function takes them as an explicit argument rather than mutating shared state.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, List, TypeVar

from app.config import conf_int

T = TypeVar("T")
R = TypeVar("R")

# Only parallelize above this many items; keep small inputs linear to avoid
# pool-creation overhead (and keep tiny scenario loads deterministic+fast).
DEFAULT_MIN_ITEMS = 2000


def parallel_workers() -> int:
    """Number of ingestion workers (config: ingestion.parallel_workers; 0=auto)."""
    workers = conf_int("ingestion.parallel_workers", 0)
    if workers and workers > 0:
        return workers
    # Auto: bounded by CPU count & a sane ceiling.
    return max(1, min(8, (os.cpu_count() or 2)))


def parallel_map(
    func: Callable[[T], R],
    items: Iterable[T],
    min_items: int = DEFAULT_MIN_ITEMS,
) -> List[R]:
    """
    Apply `func` to every item, preserving input order (NFR-R-01).

    Runs in a thread pool only when the input is large enough to warrant it;
    otherwise it degrades to a plain ordered list comprehension.
    """
    items = list(items)
    if len(items) < min_items:
        return [func(i) for i in items]

    workers = parallel_workers()
    if workers <= 1:
        return [func(i) for i in items]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        # ThreadPoolExecutor.map preserves order of the input iterable.
        return list(pool.map(func, items))
