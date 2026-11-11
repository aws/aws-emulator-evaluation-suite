"""calculate-route-matrix-travel-mode-pedestrian-vs-car."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-route-matrix-travel-mode-pedestrian-vs-car"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

DOWNTOWN_SEATTLE = [-122.3410, 47.6089]
SEATAC_AIRPORT = [-122.3088, 47.4502]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRouteMatrix must model TravelMode physics too: a Pedestrian
    entry for a ~20km pair must take substantially longer than the Car entry."""
    client = ctx.client("geo-routes")
    car_resp = client.calculate_route_matrix(
        Origins=[{"Position": DOWNTOWN_SEATTLE}],
        Destinations=[{"Position": SEATAC_AIRPORT}],
        TravelMode="Car",
    )
    ped_resp = client.calculate_route_matrix(
        Origins=[{"Position": DOWNTOWN_SEATTLE}],
        Destinations=[{"Position": SEATAC_AIRPORT}],
        TravelMode="Pedestrian",
    )

    car_entry = car_resp["RouteMatrix"][0][0]
    ped_entry = ped_resp["RouteMatrix"][0][0]
    assert car_entry.get("Error") is None, f"unexpected Car route error: {car_entry.get('Error')}"
    assert ped_entry.get("Error") is None, (
        f"unexpected Pedestrian route error: {ped_entry.get('Error')}"
    )
    assert ped_entry["Duration"] > car_entry["Duration"], (
        f"expected Pedestrian duration ({ped_entry['Duration']}s) to exceed Car duration "
        f"({car_entry['Duration']}s) for the same ~20km pair"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
