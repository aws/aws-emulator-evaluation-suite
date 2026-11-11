"""calculate-routes-waypoint-adds-leg-and-distance."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-waypoint-adds-leg-and-distance"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]  # Downtown Seattle
DESTINATION = [-122.3088, 47.4502]  # SeaTac Airport
DETOUR_WAYPOINT = [-122.2015, 47.6101]  # Bellevue -- well off the direct path


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Inserting an intermediate Waypoint that is off the direct path must split
    the route into an extra Leg and increase total travel distance."""
    client = ctx.client("geo-routes")
    direct = client.calculate_routes(Origin=ORIGIN, Destination=DESTINATION)
    detoured = client.calculate_routes(
        Origin=ORIGIN,
        Destination=DESTINATION,
        Waypoints=[{"Position": DETOUR_WAYPOINT}],
    )

    direct_route = direct["Routes"][0]
    detoured_route = detoured["Routes"][0]

    assert len(direct_route["Legs"]) == 1, (
        f"expected 1 Leg for a waypoint-free route, got {len(direct_route['Legs'])}: "
        f"{direct_route['Legs']!r}"
    )
    assert len(detoured_route["Legs"]) == 2, (
        f"expected 2 Legs after inserting an off-path Waypoint, got "
        f"{len(detoured_route['Legs'])}: {detoured_route['Legs']!r}"
    )

    direct_distance = direct_route["Summary"]["Distance"]
    detoured_distance = detoured_route["Summary"]["Distance"]
    assert detoured_distance > direct_distance, (
        f"expected detour distance ({detoured_distance}) > direct distance "
        f"({direct_distance}) after inserting an off-path Waypoint"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
