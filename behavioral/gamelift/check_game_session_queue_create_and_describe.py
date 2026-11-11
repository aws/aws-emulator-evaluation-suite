"""game-session-queue-create-and-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "game-session-queue-create-and-describe"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGameSessionQueue with no destinations succeeds and DescribeGameSessionQueues
    round-trips the queue's ARN, TimeoutInSeconds and (empty) Destinations."""
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-gsq-")

    created = gl.create_game_session_queue(
        Name=name,
        TimeoutInSeconds=45,
        Tags=[{"Key": "sim2real", "Value": "game-session-queue-create-and-describe"}],
    )["GameSessionQueue"]
    ctx.on_cleanup(lambda: gl.delete_game_session_queue(Name=name))

    assert created["Name"] == name, f"expected Name={name!r}, got {created['Name']!r}"
    assert created["TimeoutInSeconds"] == 45, (
        f"expected TimeoutInSeconds=45, got {created['TimeoutInSeconds']!r}"
    )
    assert created["Destinations"] == [], (
        f"expected no destinations on creation, got {created['Destinations']!r}"
    )
    assert created["GameSessionQueueArn"].endswith(f"gamesessionqueue/{name}"), (
        f"expected ARN ending in gamesessionqueue/{name}, got {created['GameSessionQueueArn']!r}"
    )

    described = gl.describe_game_session_queues(Names=[name])["GameSessionQueues"]
    assert len(described) == 1, f"expected exactly 1 queue named {name!r}, got {described!r}"
    assert described[0]["Name"] == name, (
        f"expected Name={name!r}, got {described[0]['Name']!r}"
    )
    assert described[0]["TimeoutInSeconds"] == 45, (
        f"expected TimeoutInSeconds=45, got {described[0]['TimeoutInSeconds']!r}"
    )
    assert described[0]["GameSessionQueueArn"] == created["GameSessionQueueArn"], (
        f"expected ARN {created['GameSessionQueueArn']!r}, got {described[0]['GameSessionQueueArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
