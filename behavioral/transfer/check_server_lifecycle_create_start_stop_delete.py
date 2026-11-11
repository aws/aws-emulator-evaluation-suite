"""server-lifecycle-create-start-stop-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-lifecycle-create-start-stop-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]

_VALID_STATES = {"OFFLINE", "ONLINE", "STARTING", "STOPPING", "START_FAILED", "STOP_FAILED"}
_CANNOT_START = "Cannot start server in the current state"
_CANNOT_STOP = "Cannot stop server in the current state"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartServer or StopServer, chosen by the new server's observed state, moves it out of that state or is
    refused with AWS's exact state message; after DeleteServer, DescribeServer and StartServer fail with
    ResourceNotFoundException "Unknown server"."""
    tf = ctx.client("transfer")
    server_id = tf.create_server(
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: _safe_delete_server(tf, server_id))

    probe = lambda: tf.describe_server(ServerId=server_id)["Server"]["State"]

    state0 = probe()
    assert state0 in _VALID_STATES, f"unexpected State value: {state0}"

    if state0 == "OFFLINE":
        # OFFLINE -> StartServer must be accepted (no exception).
        tf.start_server(ServerId=server_id)
        moved = _poll_until(probe, lambda s: s != "OFFLINE", timeout_s=20.0, interval_s=2.0)
        assert moved in ("STARTING", "ONLINE"), f"StartServer had no visible effect: {moved}"
        # Immediately trying to StopServer while still mid-transition is a real, documented
        # conflict — accept either outcome (refused now with AWS's exact state message, or
        # accepted if it already settled ONLINE).
        _accepted_or_state_refused(lambda: tf.stop_server(ServerId=server_id), _CANNOT_STOP)
    elif state0 == "ONLINE":
        # ONLINE -> StopServer must be accepted (no exception).
        tf.stop_server(ServerId=server_id)
        moved = _poll_until(probe, lambda s: s != "ONLINE", timeout_s=20.0, interval_s=2.0)
        assert moved in ("STOPPING", "OFFLINE"), f"StopServer had no visible effect: {moved}"
        _accepted_or_state_refused(lambda: tf.start_server(ServerId=server_id), _CANNOT_START)
    else:
        # Landed mid-transition (STARTING/STOPPING/*_FAILED) right after creation: both the
        # matching and opposing actions are state-dependent here, so accept either a clean call
        # or AWS's exact state-conflict refusal for each.
        _accepted_or_state_refused(lambda: tf.start_server(ServerId=server_id), _CANNOT_START)
        _accepted_or_state_refused(lambda: tf.stop_server(ServerId=server_id), _CANNOT_STOP)

    tf.delete_server(ServerId=server_id)
    code, message = _err(lambda: tf.describe_server(ServerId=server_id))
    assert code == "ResourceNotFoundException", f"expected 404 after delete, got {code}"
    assert message == "Unknown server", f"unexpected DescribeServer message after delete {message!r}"

    # A mutation against the now-dead id must also fail, not just the read.
    mutate_code, mutate_message = _err(lambda: tf.start_server(ServerId=server_id))
    assert mutate_code == "ResourceNotFoundException", (
        f"expected StartServer on a deleted ServerId to 404, got {mutate_code}"
    )
    assert mutate_message == "Unknown server", (
        f"unexpected StartServer message on a deleted ServerId {mutate_message!r}"
    )


def _safe_delete_server(tf, server_id: str) -> None:
    try:
        tf.delete_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _accepted_or_state_refused(fn, message: str) -> bool:
    """True if fn is accepted; False if refused with InvalidRequestException and exactly message."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == "InvalidRequestException", (
            f"unexpected state-conflict error code {err.get('Code')!r}"
        )
        assert err.get("Message") == message, (
            f"unexpected state-conflict message {err.get('Message')!r}"
        )
        return False
    return True


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


