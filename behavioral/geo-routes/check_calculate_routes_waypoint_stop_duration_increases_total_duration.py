"""calculate-routes-waypoint-stop-duration-increases-total-duration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-waypoint-stop-duration-increases-total-duration"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]
WAYPOINT_POSITION = [-122.3250, 47.5300]
STOP_SECONDS = 900


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Waypoint's StopDuration must be added to the overall route Duration:
    a 15-minute stop must show up as roughly a 15-minute increase in the
    total, not be silently dropped."""
    client = ctx.client("geo-routes")

    no_stop = client.calculate_routes(
        Origin=ORIGIN,
        Destination=DESTINATION,
        Waypoints=[{"Position": WAYPOINT_POSITION, "StopDuration": 0}],
    )
    with_stop = client.calculate_routes(
        Origin=ORIGIN,
        Destination=DESTINATION,
        Waypoints=[{"Position": WAYPOINT_POSITION, "StopDuration": STOP_SECONDS}],
    )

    no_stop_duration = no_stop["Routes"][0]["Summary"]["Duration"]
    with_stop_duration = with_stop["Routes"][0]["Summary"]["Duration"]
    delta = with_stop_duration - no_stop_duration
    assert abs(delta - STOP_SECONDS) < STOP_SECONDS * 0.2, (
        f"expected the {STOP_SECONDS}s stop to raise total Duration by roughly that much, "
        f"got delta={delta} (with_stop={with_stop_duration}, no_stop={no_stop_duration})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
