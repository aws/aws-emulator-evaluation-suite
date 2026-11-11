"""calculate-isolines-car-reaches-farther-than-pedestrian."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-isolines-car-reaches-farther-than-pedestrian"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
_TIME_THRESHOLD_SECONDS = 600


def _bounding_extent(isoline: dict) -> float:
    """Sum of longitude and latitude spans across every ring of every geometry -- a cheap proxy for
    how large the reachable area is."""
    points: list[list[float]] = []
    for geometry in isoline["Geometries"]:
        for ring in geometry["Polygon"]:
            points.extend(ring)
    lons = [p[0] for p in points]
    lats = [p[1] for p in points]
    return (max(lons) - min(lons)) + (max(lats) - min(lats))


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For the same 10-minute TimeThreshold, the Car isoline from one Origin covers more than twice the extent
    of the Pedestrian isoline, so travel mode shapes the isoline geometry.
    """
    client = ctx.client("geo-routes")
    car_resp = client.calculate_isolines(
        Origin=ORIGIN,
        Thresholds={"Time": [_TIME_THRESHOLD_SECONDS]},
        TravelMode="Car",
        IsolineGeometryFormat="Simple",
    )
    ped_resp = client.calculate_isolines(
        Origin=ORIGIN,
        Thresholds={"Time": [_TIME_THRESHOLD_SECONDS]},
        TravelMode="Pedestrian",
        IsolineGeometryFormat="Simple",
    )

    car_isoline = car_resp["Isolines"][0]
    ped_isoline = ped_resp["Isolines"][0]
    assert car_isoline["TimeThreshold"] == _TIME_THRESHOLD_SECONDS, (
        f"expected Car isoline TimeThreshold {_TIME_THRESHOLD_SECONDS}, got {car_isoline.get('TimeThreshold')}"
    )
    assert ped_isoline["TimeThreshold"] == _TIME_THRESHOLD_SECONDS, (
        f"expected Pedestrian isoline TimeThreshold {_TIME_THRESHOLD_SECONDS}, got {ped_isoline.get('TimeThreshold')}"
    )

    car_extent = _bounding_extent(car_isoline)
    ped_extent = _bounding_extent(ped_isoline)
    assert car_extent > ped_extent * 2, (
        f"expected Car (10-min) extent to exceed 2x the Pedestrian (10-min) extent "
        f"from the same Origin, got car_extent={car_extent}, ped_extent={ped_extent}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
