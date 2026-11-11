"""update-server-conflicting-state-blocked."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-server-conflicting-state-blocked"
GROUP = "overly-permissive"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateServer(IpAddressType=DUALSTACK) on an ONLINE server fails with InvalidRequestException and the
    documented message, leaving IpAddressType IPV4; once the server is stopped to OFFLINE the same call
    succeeds and DescribeServer reports DUALSTACK."""
    transfer = ctx.client("transfer")

    server_id = transfer.create_server()["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))
    ctx.on_cleanup(lambda: _best_effort_stop(transfer, server_id))

    probe = lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"]

    # Break: drive to ONLINE, explicitly starting it only if it has not already settled there.
    state = _poll_until(probe, predicate=lambda s: s in ("OFFLINE", "ONLINE"), timeout_s=200, interval_s=5)
    if state != "ONLINE":
        transfer.start_server(ServerId=server_id)
        state = _poll_until(probe, predicate=lambda s: s == "ONLINE", timeout_s=200, interval_s=5)
    assert state == "ONLINE", f"expected the server to settle ONLINE, got {state!r}"

    code, message = _error(
        lambda: transfer.update_server(ServerId=server_id, IpAddressType="DUALSTACK")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected_message = "Server must be OFFLINE to change IpAddressType"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: IpAddressType did not change.
    described = transfer.describe_server(ServerId=server_id)["Server"]
    assert described.get("IpAddressType", "IPV4") == "IPV4", (
        f"IpAddressType changed despite the rejected UpdateServer call, got "
        f"{described.get('IpAddressType')!r}"
    )

    # Restore: once the server is stopped back to OFFLINE, the identical call succeeds -- the
    # positive control, proving the earlier rejection was about state and not the field itself.
    transfer.stop_server(ServerId=server_id)
    _poll_until(probe, predicate=lambda s: s == "OFFLINE", timeout_s=200, interval_s=5)
    transfer.update_server(ServerId=server_id, IpAddressType="DUALSTACK")
    restored = transfer.describe_server(ServerId=server_id)["Server"]
    assert restored.get("IpAddressType") == "DUALSTACK", (
        f"UpdateServer(IpAddressType=DUALSTACK) did not persist once OFFLINE again, got "
        f"{restored.get('IpAddressType')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _best_effort_stop(transfer, server_id: str) -> None:
    try:
        transfer.stop_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

