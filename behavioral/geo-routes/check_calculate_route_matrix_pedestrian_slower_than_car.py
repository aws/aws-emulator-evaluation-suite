"""calculate-route-matrix-pedestrian-slower-than-car."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-route-matrix-pedestrian-slower-than-car"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

_ORIGIN = {"Position": [-122.3421, 47.6097]}  # Pike Place Market
_DESTINATION = {"Position": [-122.3493, 47.6205]}  # Space Needle, ~2km away


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRouteMatrix honors TravelMode per request: the same Origin/Destination
    pair produces a strictly longer Duration for Pedestrian than for Car."""
    client = ctx.client("geo-routes")
    car = client.calculate_route_matrix(
        Origins=[_ORIGIN], Destinations=[_DESTINATION], TravelMode="Car"
    )
    ped = client.calculate_route_matrix(
        Origins=[_ORIGIN], Destinations=[_DESTINATION], TravelMode="Pedestrian"
    )
    car_entry = car["RouteMatrix"][0][0]
    ped_entry = ped["RouteMatrix"][0][0]
    assert "Error" not in car_entry, f"expected a routable Car entry, got {car_entry}"
    assert "Error" not in ped_entry, f"expected a routable Pedestrian entry, got {ped_entry}"
    assert car_entry["Duration"] > 0, f"expected positive Car Duration, got {car_entry['Duration']}"
    assert ped_entry["Duration"] > 0, (
        f"expected positive Pedestrian Duration, got {ped_entry['Duration']}"
    )
    assert ped_entry["Duration"] > car_entry["Duration"], (
        f"expected walking ({ped_entry['Duration']}s) to take longer than driving "
        f"({car_entry['Duration']}s) for the same pair"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
