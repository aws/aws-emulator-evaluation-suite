"""calculate-routes-passthrough-waypoint-does-not-split-leg."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-passthrough-waypoint-does-not-split-leg"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]
WAYPOINT_POSITION = [-122.3250, 47.5300]  # roughly on the way, between the two


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Waypoint marked PassThrough=True is not treated as a stop: the route
    must still be a single Leg from Origin to Destination, unlike an ordinary
    (non-pass-through) waypoint, which splits the route into two Legs."""
    client = ctx.client("geo-routes")

    stop_resp = client.calculate_routes(
        Origin=ORIGIN,
        Destination=DESTINATION,
        Waypoints=[{"Position": WAYPOINT_POSITION}],
    )
    stop_legs = stop_resp["Routes"][0]["Legs"]
    assert len(stop_legs) == 2, (
        f"ordinary waypoint expected to split the route into 2 legs, got {len(stop_legs)}"
    )

    passthrough_resp = client.calculate_routes(
        Origin=ORIGIN,
        Destination=DESTINATION,
        Waypoints=[{"Position": WAYPOINT_POSITION, "PassThrough": True}],
    )
    passthrough_legs = passthrough_resp["Routes"][0]["Legs"]
    assert len(passthrough_legs) == 1, (
        f"PassThrough=True waypoint expected to keep a single leg, got {len(passthrough_legs)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
