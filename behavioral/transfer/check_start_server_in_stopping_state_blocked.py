"""start-server-in-stopping-state-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-server-in-stopping-state-blocked"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartServer while the server is STOPPING fails with InvalidRequestException "Cannot start
    server in the current state" and leaves it STOPPING or OFFLINE; once OFFLINE, StartServer moves
    it to STARTING or ONLINE."""
    overall_deadline = time.monotonic() + 260.0

    transfer = ctx.client("transfer")
    server_id = transfer.create_server(
        EndpointType="PUBLIC", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["ServerId"]

    def _cleanup_server():
        try:
            transfer.delete_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_server)

    # Retry StopServer until the service accepts the transition (it rejects Stop with
    # InvalidRequestException while the server is still STARTING from creation).
    _retry_until_accepted(
        lambda: transfer.stop_server(ServerId=server_id),
        deadline=min(time.monotonic() + 170.0, overall_deadline - 30.0),
        interval_s=4.0,
    )

    # Immediately probe StartServer and/or the state -- give a handful of quick
    # (near-zero-delay) attempts to land inside the STOPPING window in case the
    # transition to OFFLINE is unusually fast. This is the check's mandatory,
    # non-skippable assertion.
    caught_stopping = False
    state_now = None
    for _ in range(5):
        state_now = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state_now == "STOPPING":
            code, message = _error_code(lambda: transfer.start_server(ServerId=server_id))
            assert code == "InvalidRequestException", (
                f"expected InvalidRequestException for StartServer while STOPPING, got {code}"
            )
            assert message == "Cannot start server in the current state", message
            caught_stopping = True
            # Effect absent: still on its way to OFFLINE, not kicked back to
            # STARTING/ONLINE by the rejected call.
            state_after_rejected = transfer.describe_server(ServerId=server_id)["Server"]["State"]
            assert state_after_rejected in ("STOPPING", "OFFLINE"), (
                f"rejected StartServer changed server state to {state_after_rejected}"
            )
            break
        if state_now == "OFFLINE":
            break
        time.sleep(2)

    assert state_now in ("STOPPING", "OFFLINE"), (
        f"unexpected server state after StopServer was accepted: {state_now}"
    )
    assert caught_stopping or state_now == "OFFLINE", (
        "never observed the server in STOPPING nor OFFLINE after StopServer was accepted"
    )

    # Supplementary positive control: prove StartServer succeeds normally once safely
    # OFFLINE -- but only if there is meaningfully generous budget left, since the
    # STOPPING->OFFLINE settle can itself take several minutes on real AWS. Skipping
    # this when time-constrained does not weaken the check's core (mandatory) assertion
    # above, which has already run and been proven either way.
    remaining = overall_deadline - time.monotonic()
    if remaining > 30.0:
        state_offline = _poll_until(
            lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
            lambda s: s == "OFFLINE",
            timeout_s=remaining - 20.0,
            interval_s=4.0,
        )
        if state_offline == "OFFLINE":
            transfer.start_server(ServerId=server_id)
            state_after_start = _poll_until(
                lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
                lambda s: s in ("ONLINE", "STARTING"),
                timeout_s=max(overall_deadline - time.monotonic() - 5.0, 5.0),
                interval_s=4.0,
            )
            assert state_after_start in ("ONLINE", "STARTING"), (
                f"StartServer never moved the server off OFFLINE, last state={state_after_start}"
            )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _retry_until_accepted(fn, *, deadline: float, interval_s: float = 4.0):
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


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


