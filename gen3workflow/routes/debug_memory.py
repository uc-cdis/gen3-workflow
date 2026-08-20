"""
Temporary memory profiling endpoints. Remove before merging.
Hit GET /_debug/memory before a load test, then during/after to compare.
"""

import gc
import tracemalloc

from fastapi import APIRouter

router = APIRouter(prefix="/_debug", include_in_schema=False)

tracemalloc.start(30)
_baseline_snapshot = None


@router.get("/memory/snapshot")
def take_snapshot():
    """Take a baseline snapshot to diff against later."""
    global _baseline_snapshot
    gc.collect()
    _baseline_snapshot = tracemalloc.take_snapshot()
    return {"status": "baseline captured"}


@router.get("/memory/diff")
def diff_from_baseline():
    """
    Show what grew since the baseline snapshot.
    Hit this during or after the load test.
    """
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

    stats = current.compare_to(_baseline_snapshot, "lineno")
    grew = [s for s in stats if s.size_diff > 0][:20]
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


@router.get("/memory/large-bytes")
def inspect_large_bytes():
    """
    Find bytes objects > 500KB currently alive and show what is holding them.
    Run this during peak load, then again after load stops.
    The referrer chain tells you which layer is keeping the body alive.
    """
    gc.collect()

    large = [o for o in gc.get_objects() if isinstance(o, bytes) and len(o) > 500_000]
    large.sort(key=len, reverse=True)

    result = {
        "count": len(large),
        "total_mb": round(sum(len(b) for b in large) / 1024 / 1024, 2),
        "largest": [],
    }

    for body_bytes in large[:5]:
        chain = _referrer_chain(body_bytes, depth=6, skip={large})
        result["largest"].append(
            {
                "size_mb": round(len(body_bytes) / 1024 / 1024, 2),
                "referrer_chain": chain,
            }
        )

    return result


@router.get("/memory/gc-test")
def gc_test():
    """
    Force a full GC collection and re-measure large bytes.
    If the count drops sharply, the objects are in reference cycles
    that CPython's cycle detector can break.
    If the count stays the same, something holds a live (non-cycle) reference.
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


def _referrer_chain(obj, depth: int, skip: set) -> list:
    """Walk up the referrer graph to find what's holding `obj`."""
    chain = []
    current = obj
    for _ in range(depth):
        referrers = [
            r
            for r in gc.get_referrers(current)
            if r is not chain
            and r is not skip
            and not isinstance(r, type)
            and type(r).__name__ not in ("frame", "cell")
        ]
        if not referrers:
            break
        ref = referrers[0]
        type_name = type(ref).__name__
        module = getattr(type(ref), "__module__", "")
        chain.append(f"{module}.{type_name}" if module else type_name)
        current = ref
    return chain
