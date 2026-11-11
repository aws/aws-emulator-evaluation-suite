"""calculate-route-matrix-out-of-bounds-destination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-route-matrix-out-of-bounds-destination"
GROUP = "success-path"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]
_PORTLAND = [-122.6784, 45.5152]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A destination outside a Circle RoutingBoundary yields an entry with Error OutOfBounds and ErrorCount 1,
    while the same pair without a boundary resolves with a positive Distance.
    """
    client = ctx.client("geo-routes")

    control = client.calculate_route_matrix(
        Origins=[{"Position": _SEATTLE}],
        Destinations=[{"Position": _PORTLAND}],
        TravelMode="Car",
    )
    control_entry = control["RouteMatrix"][0][0]
    assert "Error" not in control_entry, f"expected no Error on the unbounded control, got {control_entry!r}"
    assert control_entry["Distance"] > 0, f"expected a positive Distance on the unbounded control, got {control_entry!r}"

    bounded = client.calculate_route_matrix(
        Origins=[{"Position": _SEATTLE}],
        Destinations=[{"Position": _PORTLAND}],
        TravelMode="Car",
        RoutingBoundary={"Geometry": {"Circle": {"Center": _SEATTLE, "Radius": 50000}}},
    )
    bounded_entry = bounded["RouteMatrix"][0][0]
    error_code = bounded_entry.get("Error")
    assert error_code == "OutOfBounds", (
        f"expected RouteMatrixErrorCode OutOfBounds for a Circle boundary "
        f"(confirmed against real AWS: a Circle carries no direction, so the "
        f"directional OutOfBoundsDestination/OutOfBoundsOrigin codes do not "
        f"apply here), got entry={bounded_entry!r}"
    )
    assert bounded["ErrorCount"] == 1, f"expected exactly one erroring entry, got ErrorCount={bounded['ErrorCount']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
