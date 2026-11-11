"""optimize-waypoints-before-constraint-orders-sequence."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "optimize-waypoints-before-constraint-orders-sequence"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]  # Downtown Seattle
FAR_WAYPOINT = {"Id": "far", "Position": [-122.4443, 47.2529]}  # Tacoma, ~50km away
NEAR_WAYPOINT = {"Id": "near", "Position": [-122.3430, 47.6095]}  # a block from Origin


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """OptimizeWaypoints puts the near waypoint first without constraints, and puts the far one first when it
    carries a Before constraint on the near one, with no ImpedingWaypoints either time.
    """
    client = ctx.client("geo-routes")

    unconstrained = client.optimize_waypoints(
        Origin=ORIGIN, Waypoints=[dict(FAR_WAYPOINT), dict(NEAR_WAYPOINT)]
    )
    unconstrained_ids = [
        wp["Id"] for wp in unconstrained["OptimizedWaypoints"] if "Id" in wp
    ]
    assert unconstrained_ids.index("near") < unconstrained_ids.index("far"), (
        f"expected the unconstrained optimizer to prefer the near waypoint "
        f"first (efficient sequencing), got {unconstrained_ids!r}"
    )
    assert unconstrained["ImpedingWaypoints"] == [], unconstrained["ImpedingWaypoints"]

    far_with_constraint = dict(FAR_WAYPOINT, Before=[1])
    resp = client.optimize_waypoints(
        Origin=ORIGIN, Waypoints=[far_with_constraint, NEAR_WAYPOINT]
    )

    ids_in_order = [wp["Id"] for wp in resp["OptimizedWaypoints"] if "Id" in wp]
    assert "far" in ids_in_order and "near" in ids_in_order, (
        f"expected both waypoints in OptimizedWaypoints, got {ids_in_order!r}"
    )
    assert ids_in_order.index("far") < ids_in_order.index("near"), (
        f"Before=[1] on the far waypoint must force it ahead of the near "
        f"one despite being the less efficient order, got {ids_in_order!r}"
    )
    assert resp["ImpedingWaypoints"] == [], resp["ImpedingWaypoints"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
