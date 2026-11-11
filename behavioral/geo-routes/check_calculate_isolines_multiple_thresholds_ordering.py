"""calculate-isolines-multiple-thresholds-ordering."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-isolines-multiple-thresholds-ordering"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]  # Pike Place Market, Seattle
_TIME_THRESHOLDS_SECONDS = [300, 600, 900]  # 5, 10, 15 minutes


def _extent(isoline) -> float:
    """Sum of longitude and latitude spans across every ring of every geometry --
    a cheap proxy for how large the reachable area is."""
    points = []
    for geometry in isoline["Geometries"]:
        for ring in geometry["Polygon"]:
            points.extend(ring)
    lons = [p[0] for p in points]
    lats = [p[1] for p in points]
    return (max(lons) - min(lons)) + (max(lats) - min(lats))


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateIsolines with several Time thresholds returns one isoline per threshold in request order, and
    the reachable extent does not shrink as the threshold grows.
    """
    client = ctx.client("geo-routes")
    resp = client.calculate_isolines(
        Origin=_ORIGIN,
        Thresholds={"Time": _TIME_THRESHOLDS_SECONDS},
        TravelMode="Car",
        IsolineGeometryFormat="Simple",
    )
    isolines = resp["Isolines"]
    assert len(isolines) == len(_TIME_THRESHOLDS_SECONDS), (
        f"expected {len(_TIME_THRESHOLDS_SECONDS)} isolines for "
        f"{_TIME_THRESHOLDS_SECONDS}, got {len(isolines)}"
    )
    for isoline, expected_threshold in zip(isolines, _TIME_THRESHOLDS_SECONDS):
        assert isoline["TimeThreshold"] == expected_threshold, (
            f"expected isoline in request order with TimeThreshold "
            f"{expected_threshold}, got {isoline['TimeThreshold']}"
        )

    extents = [_extent(isoline) for isoline in isolines]
    for smaller, larger in zip(extents, extents[1:]):
        assert larger >= smaller, f"expected non-decreasing extent, got {extents}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
