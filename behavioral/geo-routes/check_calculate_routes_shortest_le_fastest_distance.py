"""calculate-routes-shortest-le-fastest-distance."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-shortest-le-fastest-distance"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

# Downtown Seattle -> SeaTac Airport: ~24km with multiple plausible road choices
# (I-5 vs. Highway 99/Des Moines Memorial Dr), enough distance for route choice to matter.
_ORIGIN = [-122.3321, 47.6062]
_DESTINATION = [-122.3088, 47.4502]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """OptimizeRoutingFor=ShortestRoute must never return a longer Distance than
    OptimizeRoutingFor=FastestRoute for the identical Origin/Destination pair -- by
    definition the shortest-distance route cannot be longer than any other route."""
    client = ctx.client("geo-routes")
    shortest = client.calculate_routes(
        Origin=_ORIGIN,
        Destination=_DESTINATION,
        TravelMode="Car",
        OptimizeRoutingFor="ShortestRoute",
    )
    fastest = client.calculate_routes(
        Origin=_ORIGIN,
        Destination=_DESTINATION,
        TravelMode="Car",
        OptimizeRoutingFor="FastestRoute",
    )
    shortest_distance = shortest["Routes"][0]["Summary"]["Distance"]
    fastest_distance = fastest["Routes"][0]["Summary"]["Distance"]
    assert shortest_distance > 0 and fastest_distance > 0, (
        f"expected positive distances, got shortest={shortest_distance}m "
        f"fastest={fastest_distance}m"
    )
    assert shortest_distance <= fastest_distance, (
        f"ShortestRoute distance {shortest_distance}m exceeds FastestRoute distance "
        f"{fastest_distance}m for the same trip"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
