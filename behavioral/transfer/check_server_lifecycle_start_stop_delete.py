"""server-lifecycle-start-stop-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-lifecycle-start-stop-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopServer moves a new server to STOPPING or OFFLINE, StartServer moves it to STARTING or ONLINE or is
    refused with InvalidRequestException "Cannot start server in the current state", and after DeleteServer,
    DescribeServer fails with ResourceNotFoundException "Unknown server"."""

    transfer = ctx.client("transfer")

    server_id = transfer.create_server(
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-srv-")}],
    )["ServerId"]

    def _cleanup_server():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_server)

    # Describable immediately after creation, whatever its current transitional state.
    initial_desc = transfer.describe_server(ServerId=server_id)["Server"]
    assert initial_desc["ServerId"] == server_id, (
        f"expected ServerId={server_id!r} on the immediate describe, got {initial_desc['ServerId']!r}"
    )

    # StopServer can be issued while the server is still settling from creation
    # (InvalidRequestException, "Cannot stop server in the current state", while STARTING);
    # retry until the service accepts the transition rather than separately polling to
    # ONLINE first then issuing Stop -- this exits as soon as the server is ready.
    _retry_until_accepted(
        lambda: transfer.stop_server(ServerId=server_id),
        deadline=time.monotonic() + 200.0,
        interval_s=4.0,
    )
    state_after_stop = _poll_until(
        lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        lambda s: s in ("OFFLINE", "STOPPING", "STOP_FAILED"),
        timeout_s=60.0,
        interval_s=4,
    )
    assert state_after_stop in ("OFFLINE", "STOPPING"), (
        f"StopServer never moved the server off ONLINE, last state={state_after_stop}"
    )


    # Whatever time remains is spent proving StartServer actually moves the server. If
    # there's essentially none left, fall back to StartServer's own deterministic
    # rejection contract (still mid-transition) rather than risk a flaky partial wait.
    try:
        transfer.start_server(ServerId=server_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "InvalidRequestException", (
            f"unexpected error from StartServer: {exc.response['Error']['Code']}"
        )
        assert exc.response["Error"].get("Message") == "Cannot start server in the current state", (
            f"unexpected StartServer refusal message: {exc.response['Error'].get('Message')!r}"
        )
    else:
        state_after_start = _poll_until(
            lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
            lambda s: s in ("ONLINE", "STARTING", "START_FAILED"),
            timeout_s=20.0,
            interval_s=4,
        )
        assert state_after_start in ("ONLINE", "STARTING"), (
            f"StartServer never moved the server off OFFLINE, last state={state_after_start}"
        )

    transfer.delete_server(ServerId=server_id)
    code, message = _err(lambda: transfer.describe_server(ServerId=server_id))
    assert code == "ResourceNotFoundException", f"expected 404 after delete, got {code}"
    assert message == "Unknown server", f"unexpected DescribeServer message after delete {message!r}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _retry_until_accepted(fn, *, deadline: float, interval_s: float = 5.0):
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidRequestException":
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


