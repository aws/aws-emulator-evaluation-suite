"""start-game-session-placement-unknown-queue-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-game-session-placement-unknown-queue-rejected"
GROUP = "overly-permissive"
SERVICES = ["gamelift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartGameSessionPlacement naming a queue that does not exist fails with NotFoundException and its exact
    message and creates no placement, while the same call against an existing queue starts a placement that
    DescribeGameSessionPlacement shows.
    """
    gl = ctx.client("gamelift")
    bogus_queue = ctx.unique_name("sim2real-nonexistent-queue-")
    bad_placement_id = ctx.unique_name("sim2real-placement-bad-")

    code, message = _error(
        lambda: gl.start_game_session_placement(
            PlacementId=bad_placement_id,
            GameSessionQueueName=bogus_queue,
            MaximumPlayerSessionCount=4,
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected_message = f"Game session queue {bogus_queue} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    describe_code, describe_message = _error(
        lambda: gl.describe_game_session_placement(PlacementId=bad_placement_id)
    )
    assert describe_code == "NotFoundException", (
        f"expected the bad placement to be absent (NotFoundException), got {describe_code!r}"
    )
    expected_describe = (
        f"No GameSessionReservation found for reservation {bad_placement_id} accountId {ctx.account}"
    )
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # Positive control: a real queue accepts the placement request.
    queue_name = ctx.unique_name("sim2real-placement-queue-")
    gl.create_game_session_queue(Name=queue_name, TimeoutInSeconds=60)
    ctx.on_cleanup(lambda: gl.delete_game_session_queue(Name=queue_name))

    good_placement_id = ctx.unique_name("sim2real-placement-good-")
    started = gl.start_game_session_placement(
        PlacementId=good_placement_id,
        GameSessionQueueName=queue_name,
        MaximumPlayerSessionCount=4,
    )["GameSessionPlacement"]
    ctx.on_cleanup(lambda: _safe_stop(gl, good_placement_id))
    assert started["PlacementId"] == good_placement_id, (
        f"expected the mutating call's own response to name the placement, "
        f"got {started.get('PlacementId')!r}"
    )

    # Terminal read: an independent DescribeGameSessionPlacement, not the mutating
    # call's own response -- proves the placement is visible at the destination.
    described = gl.describe_game_session_placement(PlacementId=good_placement_id)[
        "GameSessionPlacement"
    ]
    assert described["PlacementId"] == good_placement_id, (
        f"expected PlacementId {good_placement_id!r}, got {described.get('PlacementId')!r}"
    )
    assert described["GameSessionQueueName"] == queue_name, (
        f"expected GameSessionQueueName {queue_name!r}, "
        f"got {described.get('GameSessionQueueName')!r}"
    )
    assert described["Status"] in ("PENDING", "FULFILLED"), (
        f"expected the real-queue placement to be PENDING or FULFILLED, "
        f"got {described.get('Status')!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _safe_stop(gl, placement_id):
    try:
        gl.stop_game_session_placement(PlacementId=placement_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
