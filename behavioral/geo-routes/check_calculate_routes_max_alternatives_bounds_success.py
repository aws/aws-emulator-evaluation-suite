"""calculate-routes-max-alternatives-bounds-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-max-alternatives-bounds-success"
GROUP = "success-path"
SERVICES = ["geo-routes"]

_SEATTLE = [-122.3321, 47.6062]
_PORTLAND = [-122.6784, 45.5152]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRoutes from Seattle to Portland returns at least 2 and at most MaxAlternatives + 1 routes,
    each with a positive Distance and Duration.
    """
    client = ctx.client("geo-routes")
    max_alternatives = 3
    resp = client.calculate_routes(
        Origin=_SEATTLE,
        Destination=_PORTLAND,
        TravelMode="Car",
        MaxAlternatives=max_alternatives,
    )
    routes = resp["Routes"]
    assert 2 <= len(routes) <= max_alternatives + 1, (
        f"expected between 2 (a real alternate exists for this pair) and "
        f"{max_alternatives + 1} routes for MaxAlternatives={max_alternatives}, got {len(routes)}"
    )
    for route in routes:
        summary = route["Summary"]
        assert summary["Distance"] > 0, f"expected positive route distance, got {summary['Distance']}"
        assert summary["Duration"] > 0, f"expected positive route duration, got {summary['Duration']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
