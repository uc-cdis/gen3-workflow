"""
Temporary memory profiling endpoints. Remove before merging.

The background sampler thread runs independently of the asyncio event loop,
so it continues collecting data even when the loop is saturated with uploads.

Workflow:
  1. GET /_debug/memory/snapshot   — capture tracemalloc baseline before load
  2. Run your load test
  3. GET /_debug/memory/sampled    — retrieve the full timeline collected by the thread
  4. GET /_debug/memory/gc-test    — force GC and check if objects are freed
  5. GET /_debug/memory/diff       — tracemalloc growth vs baseline
"""

import collections
import gc
import threading
import time
import tracemalloc

from fastapi import APIRouter

router = APIRouter(prefix="/_debug", include_in_schema=False)

tracemalloc.start(30)
_baseline_snapshot = None

# ── Background sampler ─────────────────────────────────────────────────────────
# Runs in a daemon thread so it is unaffected by asyncio event loop saturation.
# Stores the last SAMPLE_HISTORY samples in a circular buffer.

SAMPLE_INTERVAL_SECONDS = 3
SAMPLE_HISTORY = 200  # ~10 minutes at 3s intervals

_samples: collections.deque = collections.deque(maxlen=SAMPLE_HISTORY)
_sampler_lock = threading.Lock()


def _sample_once() -> dict:
    large = [o for o in gc.get_objects() if isinstance(o, bytes) and len(o) > 500_000]
    large.sort(key=len, reverse=True)
    largest = []
    for b in large[:3]:
        chain = _referrer_chain(b, depth=6, skip={large})
        largest.append(
            {"size_mb": round(len(b) / 1024 / 1024, 2), "referrer_chain": chain}
        )
    return {
        "ts": round(time.monotonic(), 2),
        "wall_time": time.strftime("%H:%M:%S", time.localtime()),
        "count": len(large),
        "total_kb": round(sum(len(b) for b in large) / 1024, 2),
        "total_mb": round(sum(len(b) for b in large) / 1024 / 1024, 2),
        "largest": largest,
    }


def _sampler_loop():
    while True:
        try:
            sample = _sample_once()
            with _sampler_lock:
                _samples.append(sample)
        except Exception:
            pass
        time.sleep(SAMPLE_INTERVAL_SECONDS)


_sampler_thread = threading.Thread(
    target=_sampler_loop, daemon=True, name="mem-sampler"
)
_sampler_thread.start()

# Record the start time so the test script can compute elapsed seconds.
_start_ts = time.monotonic()


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.get("/memory/snapshot")
def take_snapshot():
    """Capture a tracemalloc baseline. Call this before starting the load test."""
    global _baseline_snapshot, _start_ts
    gc.collect()
    _baseline_snapshot = tracemalloc.take_snapshot()
    with _sampler_lock:
        _samples.clear()
    _start_ts = time.monotonic()
    return {"status": "baseline captured, sample history cleared"}


@router.get("/memory/sampled")
def get_sampled():
    """
    Return the full sample timeline collected by the background thread.
    Call this after the load test — no need to poll during load.
    Elapsed seconds are relative to the last /snapshot call.
    """
    with _sampler_lock:
        samples = list(_samples)

    for s in samples:
        s["elapsed"] = round(s["ts"] - _start_ts, 1)

    return {"interval_seconds": SAMPLE_INTERVAL_SECONDS, "samples": samples}


@router.get("/memory/large-bytes")
def inspect_large_bytes():
    """
    One-shot snapshot of large bytes objects currently alive.
    Best called when the app is not under heavy load (after a test run).
    """
    gc.collect()
    large = [o for o in gc.get_objects() if isinstance(o, bytes) and len(o) > 500_000]
    large.sort(key=len, reverse=True)
    result = {
        "count": len(large),
        "total_mb": round(sum(len(b) for b in large) / 1024 / 1024, 2),
        "largest": [],
    }
    for b in large[:5]:
        chain = _referrer_chain(b, depth=6, skip={large})
        result["largest"].append(
            {"size_mb": round(len(b) / 1024 / 1024, 2), "referrer_chain": chain}
        )
    return result


@router.get("/memory/gc-test")
def gc_test():
    """
    Force gc.collect() and remeasure. If large-bytes count drops, the objects
    are in reference cycles the GC can break. If it stays flat, something holds
    a live non-cycle reference.
    """
    before = len(
        [o for o in gc.get_objects() if isinstance(o, bytes) and len(o) > 500_000]
    )
    collected = gc.collect()
    after = len(
        [o for o in gc.get_objects() if isinstance(o, bytes) and len(o) > 500_000]
    )
    return {
        "large_bytes_before_gc": before,
        "large_bytes_after_gc": after,
        "objects_collected": collected,
        "interpretation": (
            "reference cycles freed by GC"
            if after < before
            else "live references holding objects — not a cycle issue"
        ),
    }


@router.get("/memory/diff")
def diff_from_baseline():
    """Show what grew since the last /snapshot call."""
    gc.collect()
    current = tracemalloc.take_snapshot()
    if _baseline_snapshot is None:
        top = current.statistics("lineno")[:20]
        return {
            "note": "no baseline — showing absolute top allocations",
            "top": [
                {
                    "location": str(s.traceback[0]),
                    "size_kb": s.size // 1024,
                    "count": s.count,
                }
                for s in top
            ],
        }
    grew = [
        s for s in current.compare_to(_baseline_snapshot, "lineno") if s.size_diff > 0
    ][:20]
    return {
        "grew": [
            {
                "location": str(s.traceback[0]),
                "added_kb": s.size_diff // 1024,
                "added_count": s.count_diff,
            }
            for s in grew
        ]
    }


# ── Helpers ────────────────────────────────────────────────────────────────────


def _referrer_chain(obj, depth: int, skip: set) -> list:
    chain = []
    current = obj
    for _ in range(depth):
        referrers = [
            r
            for r in gc.get_referrers(current)
            if r is not chain
            and r not in skip
            and not isinstance(r, type)
            and type(r).__name__ not in ("frame", "cell")
        ]
        if not referrers:
            break
        ref = referrers[0]
        module = getattr(type(ref), "__module__", "")
        chain.append(f"{module}.{type(ref).__name__}" if module else type(ref).__name__)
        current = ref
    return chain
