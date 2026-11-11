"""calculate-routes-truck-travel-mode-options-wiring-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-truck-travel-mode-options-wiring-success"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRoutes with TravelMode Truck and truck dimension options returns a route whose legs are Truck
    legs with VehicleLegDetails.
    """
    client = ctx.client("geo-routes")
    resp = client.calculate_routes(
        Origin=ORIGIN,
        Destination=DESTINATION,
        TravelMode="Truck",
        TravelModeOptions={
            "Truck": {"GrossWeight": 15000, "Height": 400, "Length": 1600, "Width": 260}
        },
    )
    route = resp["Routes"][0]
    assert route["Summary"]["Distance"] > 0, (
        f"expected a positive route distance, got {route['Summary'].get('Distance')!r}"
    )
    for leg in route["Legs"]:
        assert leg["TravelMode"] == "Truck", (
            f"leg TravelMode was silently downgraded away from Truck: {leg['TravelMode']!r}"
        )
        assert leg.get("VehicleLegDetails"), (
            "Truck leg is missing populated VehicleLegDetails "
            f"(got {leg.get('VehicleLegDetails')!r}) despite TravelModeOptions.Truck being set"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
