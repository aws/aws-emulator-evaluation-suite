"""snap-to-roads-unmatched-point-notice."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "snap-to-roads-unmatched-point-notice"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

# Three real, close-together road fixes near downtown Seattle, plus one point far out
# in the open Pacific Ocean -- nowhere near any road, and nowhere near the other
# three points.
_TRACE_POINTS = [
    {"Position": [-122.3366, 47.6101]},
    {"Position": [-122.3363, 47.6111]},
    {"Position": [-140.0, 40.0]},  # unmatchable: open Pacific Ocean
    {"Position": [-122.3357, 47.6131]},
]
_UNMATCHABLE_INDEX = 2


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnapToRoads returns an entry for every trace point, and its notices flag the unmatchable point and none
    of the on-road points 0, 1 and 3.
    """
    client = ctx.client("geo-routes")
    resp = client.snap_to_roads(TracePoints=_TRACE_POINTS, TravelMode="Car")

    assert len(resp["SnappedTracePoints"]) == len(_TRACE_POINTS), (
        f"expected {len(_TRACE_POINTS)} snapped points, got {len(resp['SnappedTracePoints'])}"
    )

    flagged_indexes = set()
    for notice in resp["Notices"]:
        if notice["Code"] in ("TracePointsNotMatched", "TracePointsMovedByLargeDistance"):
            flagged_indexes.update(notice["TracePointIndexes"])

    assert _UNMATCHABLE_INDEX in flagged_indexes, f"no anomaly notice in {resp['Notices']}"
    assert 0 not in flagged_indexes, f"on-road point 0 wrongly flagged: {resp['Notices']}"
    assert 1 not in flagged_indexes, f"on-road point 1 wrongly flagged: {resp['Notices']}"
    assert 3 not in flagged_indexes, f"on-road point 3 wrongly flagged: {resp['Notices']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

