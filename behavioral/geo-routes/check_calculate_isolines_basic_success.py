"""calculate-isolines-basic-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-isolines-basic-success"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]  # Pike Place Market, Seattle
_TIME_THRESHOLD_SECONDS = 600  # 10 minutes


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateIsolines returns exactly one reachable-area polygon for a single Time
    threshold, echoing the requested threshold and containing real polygon geometry
    that encloses the Origin."""
    client = ctx.client("geo-routes")
    resp = client.calculate_isolines(
        Origin=_ORIGIN,
        Thresholds={"Time": [_TIME_THRESHOLD_SECONDS]},
        TravelMode="Car",
        IsolineGeometryFormat="Simple",
    )
    assert resp["IsolineGeometryFormat"] == "Simple"
    isolines = resp["Isolines"]
    assert len(isolines) == 1
    isoline = isolines[0]
    assert isoline["TimeThreshold"] == _TIME_THRESHOLD_SECONDS

    geometries = isoline["Geometries"]
    assert len(geometries) >= 1
    all_points = []
    for geometry in geometries:
        polygon = geometry["Polygon"]
        assert len(polygon) >= 1
        outer_ring = polygon[0]
        assert len(outer_ring) >= 4
        all_points.extend(outer_ring)
    lons = [p[0] for p in all_points]
    lats = [p[1] for p in all_points]
    # The reachable area must actually surround the Origin, not be some unrelated blob.
    assert min(lons) <= _ORIGIN[0] <= max(lons)
    assert min(lats) <= _ORIGIN[1] <= max(lats)
    # A bounding-box-contains-Origin check alone is nearly a tautology: any polygon big
    # enough (e.g. a fake world-sized box) trivially encloses every Origin. Bound the
    # extent to what a real 10-minute car isoline can plausibly cover, so a stub that
    # fakes geometry without computing it is caught either way.
    extent = (max(lons) - min(lons)) + (max(lats) - min(lats))
    assert 0.01 < extent < 1.0, (
        f"10-min car isoline extent {extent!r} deg is implausible "
        "(too small to be real geometry, or too large to be a real reachable area)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
