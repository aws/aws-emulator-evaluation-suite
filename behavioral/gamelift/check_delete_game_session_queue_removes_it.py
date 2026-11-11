"""delete-game-session-queue-removes-it."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-game-session-queue-removes-it"
GROUP = "state"
SERVICES = ["gamelift"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """After DeleteGameSessionQueue the queue disappears from DescribeGameSessionQueues, and
    UpdateGameSessionQueue on its name fails with InvalidRequestException 'Queue name <name> does not exist'.
    """
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-gsq-del-")
    gl.create_game_session_queue(Name=name)
    ctx.on_cleanup(lambda: _delete_queue_if_present(gl, name))

    before = gl.describe_game_session_queues(Names=[name])["GameSessionQueues"]
    assert len(before) == 1, f"expected queue {name!r} to exist before delete, got {before!r}"

    gl.delete_game_session_queue(Name=name)

    def _is_gone():
        return gl.describe_game_session_queues(Names=[name])["GameSessionQueues"] == []

    gone = _poll_until(_is_gone, lambda g: g is True, timeout_s=30.0, interval_s=2.0)
    assert gone is True, f"expected queue {name!r} to vanish from DescribeGameSessionQueues within 30s"

    code, message = _error(lambda: gl.update_game_session_queue(Name=name, TimeoutInSeconds=60))
    assert code == "InvalidRequestException", f"expected InvalidRequestException updating deleted queue {name!r}, got {code!r}"
    assert message == f"Queue name {name} does not exist", (
        f"expected GameLift's exact not-found message for deleted queue {name!r}, got {message!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_queue_if_present(gl, name):
    from botocore.exceptions import ClientError

    try:
        gl.delete_game_session_queue(Name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InvalidRequestException", "NotFoundException"):
            raise


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

