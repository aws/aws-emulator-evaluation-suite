"""snap-to-roads-notice-trace-points-not-matched."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "snap-to-roads-notice-trace-points-not-matched"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

TRACE_POINTS = [
    {"Position": [-122.3336, 47.6055]},  # downtown Seattle, on a real street
    {"Position": [-122.3339, 47.6065]},  # downtown Seattle, on a real street
    {"Position": [-140.0, 40.0]},  # open Pacific Ocean, nowhere near any road
    {"Position": [-122.3342, 47.6075]},  # downtown Seattle, on a real street (after the anomaly)
]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnapToRoads flags the open-ocean trace point at index 2 in a notice and none of the street points at
    indexes 0, 1 and 3.
    """
    client = ctx.client("geo-routes")
    resp = client.snap_to_roads(TracePoints=TRACE_POINTS)

    flagged_indexes: set[int] = set()
    for notice in resp["Notices"]:
        if notice["Code"] in ("TracePointsNotMatched", "TracePointsMovedByLargeDistance"):
            flagged_indexes.update(notice["TracePointIndexes"])
    assert 2 in flagged_indexes, f"expected index 2 (open ocean) flagged, got notices {resp['Notices']}"
    assert 0 not in flagged_indexes, f"index 0 (real street) wrongly flagged, notices {resp['Notices']}"
    assert 1 not in flagged_indexes, f"index 1 (real street) wrongly flagged, notices {resp['Notices']}"
    assert 3 not in flagged_indexes, f"index 3 (real street after anomaly) wrongly flagged, notices {resp['Notices']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

