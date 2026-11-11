"""optimize-waypoints-service-duration-reflected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "optimize-waypoints-service-duration-reflected"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

_ORIGIN = [-122.3421, 47.6097]  # Pike Place Market, Seattle
_SERVICE_DURATION_SECONDS = 600


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A waypoint's ServiceDuration appears in TimeBreakdown.ServiceDuration and adds exactly that many
    seconds to Duration compared with the same call without it.
    """
    client = ctx.client("geo-routes")
    position = [-122.3493, 47.6205]

    baseline = client.optimize_waypoints(
        Origin=_ORIGIN,
        Waypoints=[{"Id": "space-needle", "Position": position}],
    )
    serviced = client.optimize_waypoints(
        Origin=_ORIGIN,
        Waypoints=[
            {
                "Id": "space-needle",
                "Position": position,
                "ServiceDuration": _SERVICE_DURATION_SECONDS,
            }
        ],
    )

    assert baseline["TimeBreakdown"]["ServiceDuration"] == 0, (
        f"expected no ServiceDuration requested, got "
        f"{baseline['TimeBreakdown']['ServiceDuration']}"
    )
    assert serviced["TimeBreakdown"]["ServiceDuration"] == _SERVICE_DURATION_SECONDS, (
        f"expected TimeBreakdown.ServiceDuration to echo the requested "
        f"{_SERVICE_DURATION_SECONDS}, got {serviced['TimeBreakdown']['ServiceDuration']}"
    )
    # Same origin and waypoint, so travel/wait/rest should be identical between the two
    # calls -- the only thing that can move Duration is the added ServiceDuration.
    delta = serviced["Duration"] - baseline["Duration"]
    assert delta == _SERVICE_DURATION_SECONDS, (
        f"expected overall Duration to grow by exactly the added ServiceDuration "
        f"({_SERVICE_DURATION_SECONDS}s), got a delta of {delta}s "
        f"(serviced={serviced['Duration']}, baseline={baseline['Duration']})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
