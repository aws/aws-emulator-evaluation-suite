"""calculate-routes-pedestrian-slower-than-car."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-pedestrian-slower-than-car"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

# Pike Place Market -> Space Needle, Seattle: ~2km, walkable but clearly faster by car.
_ORIGIN = [-122.3421, 47.6097]
_DESTINATION = [-122.3493, 47.6205]


def _total_duration(route):
    """Route.Summary is documented optional and empirically absent for
    Pedestrian routes; sum the required per-step Duration fields (present on
    every leg type's TravelSteps) instead so both modes are compared the same
    way."""
    total = 0
    for leg in route["Legs"]:
        details = (
            leg.get("VehicleLegDetails")
            or leg.get("PedestrianLegDetails")
            or leg.get("FerryLegDetails")
            or {}
        )
        for step in details.get("TravelSteps", []):
            total += step["Duration"]
    return total


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For the same real trip, CalculateRoutes reports a Pedestrian duration strictly
    greater than the Car duration, reflecting the physical speed difference between
    the two travel modes -- not just two independently-faked numbers."""
    client = ctx.client("geo-routes")
    car = client.calculate_routes(Origin=_ORIGIN, Destination=_DESTINATION, TravelMode="Car")
    ped = client.calculate_routes(Origin=_ORIGIN, Destination=_DESTINATION, TravelMode="Pedestrian")

    car_duration = _total_duration(car["Routes"][0])
    ped_duration = _total_duration(ped["Routes"][0])

    assert car_duration > 0 and ped_duration > 0, (
        f"expected positive durations, got car={car_duration}s ped={ped_duration}s"
    )
    assert ped_duration > car_duration, (
        f"expected walking ({ped_duration}s) to take longer than driving ({car_duration}s) "
        f"for the same trip"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

