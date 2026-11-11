"""stop-game-session-placement-transitions-to-cancelled."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stop-game-session-placement-transitions-to-cancelled"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopGameSessionPlacement moves a PENDING placement (its queue has no destinations) to CANCELLED, and
    DescribeGameSessionPlacement then reports CANCELLED with an EndTime.
    """
    gl = ctx.client("gamelift")
    queue_name = ctx.unique_name("sim2real-stopplace-queue-")
    gl.create_game_session_queue(
        Name=queue_name,
        TimeoutInSeconds=600,
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: gl.delete_game_session_queue(Name=queue_name))

    placement_id = ctx.unique_name("sim2real-stopplace-")
    started = gl.start_game_session_placement(
        PlacementId=placement_id,
        GameSessionQueueName=queue_name,
        MaximumPlayerSessionCount=4,
    )["GameSessionPlacement"]
    assert started["Status"] == "PENDING", (
        f"expected freshly started placement to be PENDING, got {started['Status']!r}"
    )

    stopped = gl.stop_game_session_placement(PlacementId=placement_id)["GameSessionPlacement"]
    assert stopped["Status"] == "CANCELLED", (
        f"expected StopGameSessionPlacement response to report CANCELLED, got {stopped['Status']!r}"
    )

    final = _poll_until(
        lambda: gl.describe_game_session_placement(PlacementId=placement_id)[
            "GameSessionPlacement"
        ],
        lambda p: p["Status"] == "CANCELLED",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert final["Status"] == "CANCELLED", (
        f"expected independent DescribeGameSessionPlacement read to stay CANCELLED, "
        f"got {final['Status']!r}"
    )
    assert "EndTime" in final, f"expected a CANCELLED placement to carry EndTime, got keys {sorted(final)}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
