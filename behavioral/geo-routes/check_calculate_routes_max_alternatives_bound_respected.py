"""calculate-routes-max-alternatives-bound-respected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-max-alternatives-bound-respected"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

# Downtown Seattle -> SeaTac Airport: long enough for multiple plausible alternatives to exist.
_ORIGIN = [-122.3321, 47.6062]
_DESTINATION = [-122.3088, 47.4502]
_MAX_ALTERNATIVES = 2


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRoutes returns one route with MaxAlternatives 0, and more than one but at most 3 routes with
    MaxAlternatives 2, each with a positive Distance and Duration.
    """
    client = ctx.client("geo-routes")
    baseline = client.calculate_routes(
        Origin=_ORIGIN, Destination=_DESTINATION, TravelMode="Car", MaxAlternatives=0
    )
    baseline_routes = baseline["Routes"]
    assert len(baseline_routes) == 1, (
        f"expected exactly the primary route at MaxAlternatives=0, got {len(baseline_routes)}"
    )

    resp = client.calculate_routes(
        Origin=_ORIGIN,
        Destination=_DESTINATION,
        TravelMode="Car",
        MaxAlternatives=_MAX_ALTERNATIVES,
    )
    routes = resp["Routes"]
    assert 1 <= len(routes) <= _MAX_ALTERNATIVES + 1, (
        f"expected between 1 and {_MAX_ALTERNATIVES + 1} routes, got {len(routes)}"
    )
    assert len(routes) > len(baseline_routes), (
        f"MaxAlternatives={_MAX_ALTERNATIVES} returned {len(routes)} route(s), no more than the "
        f"MaxAlternatives=0 baseline of {len(baseline_routes)} -- the parameter had no observable effect"
    )
    for route in routes:
        assert route["Summary"]["Distance"] > 0, (
            f"route Summary.Distance must be positive, got {route['Summary']['Distance']}"
        )
        assert route["Summary"]["Duration"] > 0, (
            f"route Summary.Duration must be positive, got {route['Summary']['Duration']}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
