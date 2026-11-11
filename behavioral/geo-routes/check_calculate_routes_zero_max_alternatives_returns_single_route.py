"""calculate-routes-zero-max-alternatives-returns-single-route."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-zero-max-alternatives-returns-single-route"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """MaxAlternatives=0 means "no alternatives": exactly the single primary
    route must be returned, never a padded list of duplicates or extras."""
    client = ctx.client("geo-routes")
    resp = client.calculate_routes(
        Origin=ORIGIN, Destination=DESTINATION, MaxAlternatives=0
    )
    routes = resp["Routes"]
    assert len(routes) == 1, f"expected exactly 1 route (no alternatives), got {len(routes)}"
    summary = routes[0]["Summary"]
    assert summary["Distance"] > 0, f"expected positive Distance, got {summary['Distance']}"
    assert summary["Duration"] > 0, f"expected positive Duration, got {summary['Duration']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
