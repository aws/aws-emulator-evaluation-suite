"""snap-to-roads-duplicate-trace-points-each-snapped-independently."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "snap-to-roads-duplicate-trace-points-each-snapped-independently"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

POINT = [-122.3336, 47.6055]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Submitting the exact same Position twice as separate TracePoints must
    not be deduplicated: the response must still contain one
    SnappedTracePoint per input entry, both snapping to the same road."""
    client = ctx.client("geo-routes")
    resp = client.snap_to_roads(TracePoints=[{"Position": POINT}, {"Position": POINT}])

    snapped = resp["SnappedTracePoints"]
    assert len(snapped) == 2, f"expected one SnappedTracePoint per duplicate input, got {len(snapped)}"
    assert snapped[0]["SnappedPosition"] == snapped[1]["SnappedPosition"], (
        f"identical inputs must snap identically, got {snapped[0]['SnappedPosition']} "
        f"vs {snapped[1]['SnappedPosition']}"
    )
    assert snapped[0]["OriginalPosition"] == POINT, f"expected {POINT}, got {snapped[0]['OriginalPosition']}"
    assert snapped[1]["OriginalPosition"] == POINT, f"expected {POINT}, got {snapped[1]['OriginalPosition']}"
    assert 0.0 <= snapped[0]["Confidence"] <= 1.0, f"Confidence out of range: {snapped[0]['Confidence']}"
    assert snapped[0]["Confidence"] == snapped[1]["Confidence"], (
        f"identical inputs must yield identical Confidence, got {snapped[0]['Confidence']} "
        f"vs {snapped[1]['Confidence']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
