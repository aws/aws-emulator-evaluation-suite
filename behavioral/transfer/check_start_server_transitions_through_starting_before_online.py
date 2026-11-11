"""start-server-transitions-through-starting-before-online."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-server-transitions-through-starting-before-online"
GROUP = "visibility-timeout-ttl"
SERVICES = ["transfer"]

_SETTLED = {"ONLINE", "OFFLINE", "START_FAILED", "STOP_FAILED"}


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a new server settles ONLINE and is stopped to OFFLINE, DescribeServer reports STARTING
    right after StartServer and the server then reaches ONLINE: the start has an observable
    transient state."""
    transfer = ctx.client("transfer")
    server_id = transfer.create_server(
        Protocols=["SFTP"], Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["ServerId"]
    ctx.on_cleanup(lambda: _delete_server(ctx, server_id))

    settled = _poll_until_state(ctx, server_id, {"ONLINE", "START_FAILED"}, timeout_s=900)
    assert settled == "ONLINE", f"new server settled in {settled} instead of ONLINE"
    transfer.stop_server(ServerId=server_id)
    stopped = _poll_until_state(ctx, server_id, {"OFFLINE", "STOP_FAILED"}, timeout_s=900)
    assert stopped == "OFFLINE", f"stopped server settled in {stopped} instead of OFFLINE"

    transfer.start_server(ServerId=server_id)
    immediate_state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
    # The state machine must expose a real transient step -- if AWS/emulator flips
    # straight to ONLINE with no observable STARTING window, that's the failure mode
    # this check exists to catch.
    assert immediate_state == "STARTING", (
        f"expected STARTING immediately after StartServer on an OFFLINE server, got "
        f"{immediate_state} (server flipped with no observable transition window)"
    )

    final_state = _poll_until_state(ctx, server_id, {"ONLINE", "START_FAILED"}, timeout_s=900)
    assert final_state == "ONLINE", f"server ended in {final_state} instead of ONLINE"


def _poll_until_state(ctx, server_id: str, target_states: set, timeout_s: float) -> str:
    transfer = ctx.client("transfer")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state in target_states:
            return state
        time.sleep(5)
    raise AssertionError(f"server {server_id} never reached {target_states}, last state {state}")


def _delete_server(ctx, server_id: str) -> None:
    """Wait for a settled state (a server mid-transition refuses DeleteServer), delete the
    server and wait until it is gone."""
    transfer = ctx.client("transfer")
    try:
        _poll_until_state(ctx, server_id, _SETTLED, timeout_s=900)
        transfer.delete_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            transfer.describe_server(ServerId=server_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(10)
    raise AssertionError(f"server {server_id} still present 600s after DeleteServer")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
