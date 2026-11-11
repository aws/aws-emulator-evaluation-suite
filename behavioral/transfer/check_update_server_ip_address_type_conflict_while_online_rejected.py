"""update-server-ip-address-type-conflict-while-online-rejected."""
from __future__ import annotations

import time

CHECK = "update-server-ip-address-type-conflict-while-online-rejected"
GROUP = "deploy"
SERVICES = ["transfer"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateServer rejects an IpAddressType change with InvalidRequestException while
    the server is ONLINE; the field is left unchanged, and the identical update
    succeeds once the server is stopped (positive control in the same file)."""
    transfer = ctx.client("transfer")

    server_id = transfer.create_server(
        Protocols=["SFTP"], Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    # Settle to a known starting state, then make sure the server is ONLINE for the
    # negative half of this check (a fresh server may already start OFFLINE or ONLINE).
    state = _poll_until(
        lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        lambda s: s in ("OFFLINE", "ONLINE"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    if state != "ONLINE":
        transfer.start_server(ServerId=server_id)
        state = _poll_until(
            lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
            lambda s: s == "ONLINE",
            timeout_s=300.0,
            interval_s=10.0,
        )
    assert state == "ONLINE", f"expected server to reach ONLINE, got {state!r}"

    original_ip_type = transfer.describe_server(ServerId=server_id)["Server"].get("IpAddressType", "IPV4")

    code, message = _error(lambda: transfer.update_server(ServerId=server_id, IpAddressType="DUALSTACK"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException while ONLINE, got {code!r}"
    expected_message = "Server must be OFFLINE to change IpAddressType"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected update must not have taken effect.
    unchanged = transfer.describe_server(ServerId=server_id)["Server"].get("IpAddressType", "IPV4")
    assert unchanged == original_ip_type, "IpAddressType changed despite the rejected UpdateServer call"

    # Positive control: the identical call succeeds once the server is OFFLINE.
    transfer.stop_server(ServerId=server_id)
    _poll_until(
        lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        lambda s: s == "OFFLINE",
        timeout_s=240.0,
        interval_s=10.0,
    )
    transfer.update_server(ServerId=server_id, IpAddressType="DUALSTACK")
    updated = transfer.describe_server(ServerId=server_id)["Server"].get("IpAddressType")
    assert updated == "DUALSTACK", "UpdateServer(IpAddressType=DUALSTACK) did not persist while OFFLINE"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"].get("Code"), err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
