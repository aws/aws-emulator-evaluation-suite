"""snap-to-roads-not-matched-notice."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "snap-to-roads-not-matched-notice"
GROUP = "success-path"
SERVICES = ["geo-routes"]

# Three real, close-together road fixes near downtown Seattle, plus one point far
# out in the open Pacific Ocean -- nowhere near any road -- so the response is
# guaranteed to carry at least one notice under Truck mode as well as Car mode.
_TRACE_POINTS = [
    [-122.3421, 47.6101],
    [-122.3428, 47.6110],
    [-122.3433, 47.6120],
    [-140.0, 40.0],
]
_UNMATCHABLE_INDEX = 3


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnapToRoads with TravelMode Truck and truck options snaps every point, and its notices flag the
    off-road trace point and none of the on-road ones.
    """
    client = ctx.client("geo-routes")
    resp = client.snap_to_roads(
        TracePoints=[{"Position": p} for p in _TRACE_POINTS],
        TravelMode="Truck",
        TravelModeOptions={
            "Truck": {
                "GrossWeight": 12000,
                "Height": 400,
                "Length": 1200,
                "Width": 250,
            }
        },
    )
    snapped = resp["SnappedTracePoints"]
    assert len(snapped) == len(_TRACE_POINTS)
    for point in snapped:
        assert 0.0 <= point["Confidence"] <= 1.0
        assert len(point["SnappedPosition"]) == 2

    # Exactly one notice: the off-road point is flagged as moved a large distance, and none of
    # the on-road points is flagged.
    assert resp["Notices"] == [
        {"Code": "TracePointsMovedByLargeDistance", "TracePointIndexes": [_UNMATCHABLE_INDEX]}
    ], f"expected a single TracePointsMovedByLargeDistance notice for index 3, got {resp['Notices']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
