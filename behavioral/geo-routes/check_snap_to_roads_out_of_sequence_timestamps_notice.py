"""snap-to-roads-out-of-sequence-timestamps-notice."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "snap-to-roads-out-of-sequence-timestamps-notice"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

TRACE_POINTS = [
    {"Position": [-122.3336, 47.6055], "Timestamp": "2024-01-01T12:00:30Z"},
    {"Position": [-122.3339, 47.6065], "Timestamp": "2024-01-01T12:00:10Z"},
    {"Position": [-122.3342, 47.6075], "Timestamp": "2024-01-01T12:00:50Z"},
]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SnapToRoads with mildly out-of-order Timestamps returns one snapped point per trace point, paired with
    its OriginalPosition and within 0.02 degrees of it, and no Notices.
    """
    client = ctx.client("geo-routes")
    resp = client.snap_to_roads(TracePoints=TRACE_POINTS)

    snapped = resp["SnappedTracePoints"]
    assert len(snapped) == len(TRACE_POINTS), f"expected {len(TRACE_POINTS)} points, got {len(snapped)}"
    for original, snap in zip(TRACE_POINTS, snapped):
        assert snap["OriginalPosition"] == original["Position"], (
            f"expected {original['Position']}, got {snap['OriginalPosition']}"
        )
        assert 0.0 <= snap["Confidence"] <= 1.0, f"Confidence out of range: {snap['Confidence']}"
        snapped_position = snap["SnappedPosition"]
        assert len(snapped_position) == 2, f"expected a [lon, lat] pair, got {snapped_position}"
        lon_delta = abs(snapped_position[0] - original["Position"][0])
        lat_delta = abs(snapped_position[1] - original["Position"][1])
        assert lon_delta < 0.02 and lat_delta < 0.02, (
            f"snapped position {snapped_position} too far from raw fix {original['Position']}"
        )

    assert resp["Notices"] == [], f"expected no Notices for mildly out-of-order timestamps, got {resp['Notices']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

