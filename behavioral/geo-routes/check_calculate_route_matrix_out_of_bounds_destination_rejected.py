"""calculate-route-matrix-out-of-bounds-destination-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-route-matrix-out-of-bounds-destination-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-routes"]

_ORIGIN = {"Position": [-122.3321, 47.6062]}  # Downtown Seattle
_IN_BOUNDS_DESTINATION = {"Position": [-122.1963, 47.6101]}  # Bellevue -- inside the box
_OUT_OF_BOUNDS_DESTINATION = {"Position": [-122.3088, 47.4502]}  # SeaTac -- south of the box
# Covers downtown Seattle and Bellevue, but not SeaTac (which sits south of lat 47.55).
_BOUNDING_BOX = [-122.40, 47.55, -122.15, 47.65]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BoundingBox RoutingBoundary that excludes one destination flags only that entry as out of bounds,
    with ErrorCount 1, while the in-bounds entry routes; without the boundary both entries route.
    """
    client = ctx.client("geo-routes")

    bounded = client.calculate_route_matrix(
        Origins=[_ORIGIN],
        Destinations=[_IN_BOUNDS_DESTINATION, _OUT_OF_BOUNDS_DESTINATION],
        RoutingBoundary={"Geometry": {"BoundingBox": _BOUNDING_BOX}},
    )
    row = bounded["RouteMatrix"][0]
    in_bounds_entry, out_of_bounds_entry = row[0], row[1]

    assert "Error" not in in_bounds_entry
    assert in_bounds_entry["Distance"] > 0

    assert out_of_bounds_entry.get("Error") in {
        "OutOfBounds",
        "OutOfBoundsDestination",
    }, (
        f"expected an out-of-bounds RouteMatrixErrorCode, got {out_of_bounds_entry.get('Error')!r}"
    )
    assert bounded["ErrorCount"] == 1

    # Positive control: lifting the boundary restriction lets the same pair resolve.
    unbounded = client.calculate_route_matrix(
        Origins=[_ORIGIN],
        Destinations=[_OUT_OF_BOUNDS_DESTINATION],
        RoutingBoundary={"Unbounded": True},
    )
    entry = unbounded["RouteMatrix"][0][0]
    assert "Error" not in entry
    assert entry["Distance"] > 0


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
