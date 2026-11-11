"""optimize-waypoints-origin-and-destination-no-waypoints-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "optimize-waypoints-origin-and-destination-no-waypoints-success"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """With Origin and Destination but zero intermediate Waypoints, the
    optimized sequence degenerates to exactly the two endpoints connected by
    a single Connection, with a positive overall Distance/Duration."""
    client = ctx.client("geo-routes")
    resp = client.optimize_waypoints(Origin=ORIGIN, Destination=DESTINATION)

    optimized = resp["OptimizedWaypoints"]
    connections = resp["Connections"]
    assert len(optimized) == 2, f"expected exactly Origin+Destination (2), got {optimized!r}"
    assert len(connections) == 1, f"expected exactly one hop, got {connections!r}"
    assert resp["Distance"] > 0, f"expected a positive overall Distance, got {resp['Distance']!r}"
    assert resp["Duration"] > 0, f"expected a positive overall Duration, got {resp['Duration']!r}"
    assert resp["ImpedingWaypoints"] == [], (
        f"expected no impeding waypoints, got {resp['ImpedingWaypoints']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
