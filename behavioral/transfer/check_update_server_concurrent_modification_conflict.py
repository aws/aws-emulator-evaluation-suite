"""update-server-concurrent-modification-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "update-server-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateServer(IpAddressType=DUALSTACK) calls on an ONLINE server both fail with the same
    InvalidRequestException and message and leave IpAddressType unchanged, while an UpdateServer of the banner on
    the same ONLINE server succeeds."""
    transfer = ctx.client("transfer")
    server_id = transfer.create_server(
        Protocols=["SFTP"],
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-transfer-concurrent-srv-")}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    original_ip_type = transfer.describe_server(ServerId=server_id)["Server"].get("IpAddressType", "IPV4")
    assert original_ip_type != "DUALSTACK", (
        f"expected a fresh server to default to a non-DUALSTACK IpAddressType, got {original_ip_type!r}"
    )

    transfer.start_server(ServerId=server_id)
    ctx.on_cleanup(lambda: transfer.stop_server(ServerId=server_id))
    _wait_for_state(ctx, server_id, {"ONLINE"}, timeout_s=260)

    barrier = threading.Barrier(2)

    def _attempt():
        barrier.wait(timeout=10)
        return _error(
            lambda: transfer.update_server(ServerId=server_id, IpAddressType="DUALSTACK")
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        errors = list(pool.map(lambda _: _attempt(), range(2)))

    expected_message = "Server must be OFFLINE to change IpAddressType"
    expected_error = ("InvalidRequestException", expected_message)
    assert errors == [expected_error, expected_error], (
        f"expected both concurrent ONLINE-state updates to be consistently rejected "
        f"(no race window letting one through) with {expected_error!r}, got {errors}"
    )

    # Effect absent: the field is untouched by either rejected attempt.
    unchanged = transfer.describe_server(ServerId=server_id)["Server"].get("IpAddressType", "IPV4")
    assert unchanged == original_ip_type, (
        f"expected IpAddressType to stay {original_ip_type!r} after both rejected racers, got {unchanged!r}"
    )

    # Positive control: an unrestricted field update on the same still-ONLINE
    # server succeeds -- UpdateServer itself isn't blocked while ONLINE, only
    # the state-guarded IpAddressType field is.
    transfer.update_server(ServerId=server_id, PreAuthenticationLoginBanner="sim2real-online-update-ok")
    updated_banner = transfer.describe_server(ServerId=server_id)["Server"]["PreAuthenticationLoginBanner"]
    assert updated_banner == "sim2real-online-update-ok", (
        f"expected the unrestricted-field update to persist while ONLINE, got {updated_banner!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_for_state(ctx, server_id: str, target_states: set, timeout_s: float) -> str:
    transfer = ctx.client("transfer")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = transfer.describe_server(ServerId=server_id)["Server"]["State"]
        if state in target_states:
            return state
        time.sleep(3)
    raise AssertionError(f"server {server_id} never reached {target_states}, last state {state}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


