"""update-game-session-queue-persists-changes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-game-session-queue-persists-changes"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGameSessionQueue replaces TimeoutInSeconds and PlayerLatencyPolicies;
    the change is durable and visible on a subsequent DescribeGameSessionQueues,
    not just in the UpdateGameSessionQueue response."""
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-gsq-upd-")
    gl.create_game_session_queue(
        Name=name,
        TimeoutInSeconds=30,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: gl.delete_game_session_queue(Name=name))

    updated = gl.update_game_session_queue(
        Name=name,
        TimeoutInSeconds=120,
        PlayerLatencyPolicies=[
            {"MaximumIndividualPlayerLatencyMilliseconds": 200, "PolicyDurationSeconds": 60}
        ],
    )["GameSessionQueue"]
    assert updated["TimeoutInSeconds"] == 120, (
        f"expected updated TimeoutInSeconds=120, got {updated['TimeoutInSeconds']!r}"
    )
    assert len(updated["PlayerLatencyPolicies"]) == 1, (
        f"expected 1 PlayerLatencyPolicies on update response, "
        f"got {updated['PlayerLatencyPolicies']!r}"
    )

    described = gl.describe_game_session_queues(Names=[name])["GameSessionQueues"][0]
    assert described["TimeoutInSeconds"] == 120, (
        f"expected DescribeGameSessionQueues TimeoutInSeconds=120, "
        f"got {described['TimeoutInSeconds']!r}"
    )
    assert len(described["PlayerLatencyPolicies"]) == 1, (
        f"expected 1 PlayerLatencyPolicies on independent describe, "
        f"got {described['PlayerLatencyPolicies']!r}"
    )
    assert (
        described["PlayerLatencyPolicies"][0]["MaximumIndividualPlayerLatencyMilliseconds"]
        == 200
    ), (
        f"expected MaximumIndividualPlayerLatencyMilliseconds=200 on independent describe, "
        f"got {described['PlayerLatencyPolicies'][0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
