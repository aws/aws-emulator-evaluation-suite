"""calculate-routes-and-route-matrix-agree-on-distance."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-and-route-matrix-agree-on-distance"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For the same Car origin and destination, CalculateRoutes and CalculateRouteMatrix report positive
    distances that differ by less than 20%.
    """
    client = ctx.client("geo-routes")

    routes_resp = client.calculate_routes(
        Origin=ORIGIN, Destination=DESTINATION, TravelMode="Car"
    )
    matrix_resp = client.calculate_route_matrix(
        Origins=[{"Position": ORIGIN}],
        Destinations=[{"Position": DESTINATION}],
        TravelMode="Car",
    )

    route_distance = routes_resp["Routes"][0]["Summary"]["Distance"]
    matrix_entry = matrix_resp["RouteMatrix"][0][0]
    assert matrix_entry.get("Error") is None, (
        f"expected a routable matrix entry, got Error={matrix_entry.get('Error')!r}"
    )
    matrix_distance = matrix_entry["Distance"]

    assert route_distance > 0 and matrix_distance > 0, (
        f"expected both distances > 0, got route_distance={route_distance}, "
        f"matrix_distance={matrix_distance}"
    )
    ratio = max(route_distance, matrix_distance) / min(route_distance, matrix_distance)
    assert ratio < 1.2, (
        f"expected CalculateRoutes and CalculateRouteMatrix distances to agree within 20% "
        f"for the same Origin/Destination, got route_distance={route_distance}, "
        f"matrix_distance={matrix_distance}, ratio={ratio:.3f}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
