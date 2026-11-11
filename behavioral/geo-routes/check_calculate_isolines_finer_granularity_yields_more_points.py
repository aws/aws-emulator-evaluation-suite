"""calculate-isolines-finer-granularity-yields-more-points."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-isolines-finer-granularity-yields-more-points"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]


def _point_count(resp) -> int:
    ring = resp["Isolines"][0]["Geometries"][0]["Polygon"][0]
    return len(ring)


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For the same 5000 m DistanceThreshold, a fine IsolineGranularity.MaxResolution yields more boundary
    points than a coarse one.
    """
    client = ctx.client("geo-routes")

    coarse = client.calculate_isolines(
        Origin=ORIGIN,
        Thresholds={"Distance": [5000]},
        IsolineGeometryFormat="Simple",
        IsolineGranularity={"MaxResolution": 5000},
    )
    fine = client.calculate_isolines(
        Origin=ORIGIN,
        Thresholds={"Distance": [5000]},
        IsolineGeometryFormat="Simple",
        IsolineGranularity={"MaxResolution": 50},
    )

    assert coarse["Isolines"][0]["DistanceThreshold"] == 5000
    assert fine["Isolines"][0]["DistanceThreshold"] == 5000

    coarse_points = _point_count(coarse)
    fine_points = _point_count(fine)
    assert coarse_points >= 3, coarse_points
    assert fine_points > coarse_points, (fine_points, coarse_points)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
