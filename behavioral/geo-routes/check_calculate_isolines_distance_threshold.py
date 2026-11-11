"""calculate-isolines-distance-threshold."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-isolines-distance-threshold"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]  # Pike Place Market, Seattle
_DISTANCE_THRESHOLD_METERS = 2000


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A distance-based Thresholds.Distance request returns an Isoline whose
    DistanceThreshold echoes the request (not a TimeThreshold), proving distance-mode
    and time-mode isolines are actually distinguished server-side."""
    client = ctx.client("geo-routes")
    resp = client.calculate_isolines(
        Origin=_ORIGIN,
        Thresholds={"Distance": [_DISTANCE_THRESHOLD_METERS]},
        TravelMode="Car",
        IsolineGeometryFormat="Simple",
    )
    isolines = resp["Isolines"]
    assert len(isolines) == 1, f"expected exactly 1 isoline, got {len(isolines)}"
    isoline = isolines[0]
    assert isoline["DistanceThreshold"] == _DISTANCE_THRESHOLD_METERS, (
        f"expected DistanceThreshold {_DISTANCE_THRESHOLD_METERS}, got {isoline['DistanceThreshold']}"
    )
    # Distance-mode isolines omit TimeThreshold entirely; it is absent, not zero.
    assert "TimeThreshold" not in isoline, f"unexpected TimeThreshold on a distance-mode isoline: {isoline.get('TimeThreshold')}"
    assert len(isoline["Geometries"]) >= 1, "expected at least one geometry in the isoline"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
