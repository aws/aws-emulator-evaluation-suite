"""e2e-optimize-waypoints-then-calculate-routes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-optimize-waypoints-then-calculate-routes"
GROUP = "e2e"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3493, 47.6205]  # Space Needle
_DESTINATION = [-122.3344, 47.6015]  # Pioneer Square
_STOP_A = [-122.3421, 47.6101]  # Pike Place Market
_STOP_B = [-122.3358, 47.6132]  # near Seattle Central Library
_STOP_C = [-122.3541, 47.6206]  # Seattle Center


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The stop order OptimizeWaypoints returns, sent to CalculateRoutes as Waypoints, yields one leg per hop
    and a total distance between 0.4 and 2.5 times the optimizer's Distance.
    """
    client = ctx.client("geo-routes")

    optimized = client.optimize_waypoints(
        Origin=_ORIGIN,
        Destination=_DESTINATION,
        TravelMode="Car",
        Waypoints=[
            {"Id": "stop-a", "Position": _STOP_A},
            {"Id": "stop-b", "Position": _STOP_B},
            {"Id": "stop-c", "Position": _STOP_C},
        ],
    )
    assert optimized["ImpedingWaypoints"] == [], (
        f"expected no impeding waypoints for 3 reachable stops, got "
        f"ImpedingWaypoints={optimized['ImpedingWaypoints']!r}"
    )
    ordered_stops = [w for w in optimized["OptimizedWaypoints"] if w.get("Id") in
                      {"stop-a", "stop-b", "stop-c"}]
    assert {w["Id"] for w in ordered_stops} == {"stop-a", "stop-b", "stop-c"}, (
        f"expected exactly the 3 supplied stops, got OptimizedWaypoints={optimized['OptimizedWaypoints']!r}"
    )
    optimizer_distance = optimized["Distance"]
    assert optimizer_distance > 0, (
        f"expected a positive optimizer Distance, got {optimizer_distance!r}"
    )


    routed = client.calculate_routes(
        Origin=_ORIGIN,
        Destination=_DESTINATION,
        TravelMode="Car",
        Waypoints=[{"Position": w["Position"]} for w in ordered_stops],
    )
    routes = routed["Routes"]
    assert len(routes) >= 1, f"expected at least one route, got {routes!r}"
    route = routes[0]

    # Origin -> stop -> stop -> stop -> Destination = 4 legs for 3 waypoints.
    legs = route["Legs"]
    assert len(legs) == len(ordered_stops) + 1, (
        f"expected {len(ordered_stops) + 1} legs for {len(ordered_stops)} "
        f"waypoints, got {len(legs)} legs"
    )

    route_distance = route["Summary"]["Distance"]
    assert route_distance > 0, (
        f"expected a positive route Distance, got {route_distance!r}"
    )

    # The two operations tune their routing independently, so exact equality is not expected, but their
    # distances for the same stop sequence must agree within a generous factor.
    ratio = route_distance / optimizer_distance
    assert 0.4 <= ratio <= 2.5, (
        f"CalculateRoutes distance {route_distance} and OptimizeWaypoints "
        f"distance {optimizer_distance} disagree wildly for the same stop "
        f"sequence (ratio={ratio:.2f})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

