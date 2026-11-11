"""snap-to-roads-basic-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "snap-to-roads-basic-success"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

# A handful of GPS fixes roughly along 5th Ave, Seattle, heading north.
_TRACE_POINTS = [
    {"Position": [-122.3366, 47.6101]},
    {"Position": [-122.3363, 47.6111]},
    {"Position": [-122.3360, 47.6121]},
    {"Position": [-122.3357, 47.6131]},
]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnapToRoads returns one snapped point per trace point, echoing its OriginalPosition with a Confidence
    in [0, 1] and a SnappedPosition within 0.02 degrees; at least one point moves and the confidences are not
    all equal.
    """
    client = ctx.client("geo-routes")
    resp = client.snap_to_roads(TracePoints=_TRACE_POINTS, TravelMode="Car")

    snapped = resp["SnappedTracePoints"]
    assert len(snapped) == len(_TRACE_POINTS), (
        f"expected {len(_TRACE_POINTS)} SnappedTracePoints, got {len(snapped)}: {snapped}"
    )
    confidences = []
    moved = []
    for original, snap in zip(_TRACE_POINTS, snapped):
        confidence = snap["Confidence"]
        assert 0.0 <= confidence <= 1.0, f"Confidence out of [0,1]: {confidence}"
        assert snap["OriginalPosition"] == original["Position"], (
            f"OriginalPosition {snap['OriginalPosition']} != request Position {original['Position']}"
        )
        snapped_position = snap["SnappedPosition"]
        assert len(snapped_position) == 2, f"SnappedPosition must be [lon, lat], got {snapped_position}"
        # The snap must land close to the raw fix (within roughly ~2km).
        lon_delta = abs(snapped_position[0] - original["Position"][0])
        lat_delta = abs(snapped_position[1] - original["Position"][1])
        assert lon_delta < 0.02 and lat_delta < 0.02, (
            f"snapped position {snapped_position} too far from raw fix {original['Position']} "
            f"(lon_delta={lon_delta}, lat_delta={lat_delta})"
        )
        confidences.append(confidence)
        moved.append(tuple(snapped_position) != tuple(original["Position"]))

    # A target that just echoes the input back (identity map, constant confidence)
    # must not pass as a real map-matcher: real AWS moves at least one of these
    # off-road GPS fixes and reports materially different confidence per point.
    assert any(moved), f"no SnappedPosition differs from its raw fix: {snapped}"
    assert len(set(confidences)) > 1, f"every Confidence is identical, no real per-point scoring: {confidences}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
