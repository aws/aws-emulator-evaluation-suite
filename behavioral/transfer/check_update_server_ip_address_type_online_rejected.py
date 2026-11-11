"""update-server-ip-address-type-online-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-server-ip-address-type-online-rejected"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateServer(IpAddressType=...) while the server is ONLINE is rejected with
    InvalidRequestException, the setting is left unchanged, and the identical call
    succeeds once the server is stopped (positive control, same file)."""
    tf = ctx.client("transfer")
    server_id = tf.create_server(Tags=[{"Key": "sim2real", "Value": CHECK}])["ServerId"]
    ctx.on_cleanup(lambda: _safe_delete_server(tf, server_id))

    # A fresh server may already report OFFLINE or (transiently, mid-provisioning)
    # ONLINE by the time the first read lands — settle to whichever it is, then force
    # ONLINE for the negative half of this check.
    state = _poll_until(
        lambda: tf.describe_server(ServerId=server_id)["Server"]["State"],
        lambda s: s in ("OFFLINE", "ONLINE"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    if state != "ONLINE":
        tf.start_server(ServerId=server_id)
        state = _poll_until(
            lambda: tf.describe_server(ServerId=server_id)["Server"]["State"],
            lambda s: s == "ONLINE",
            timeout_s=240.0,
            interval_s=10.0,
        )
    assert state == "ONLINE", f"server did not reach ONLINE, ended at {state}"

    original_ip_type = tf.describe_server(ServerId=server_id)["Server"].get("IpAddressType", "IPV4")
    assert original_ip_type == "IPV4", f"expected a fresh server to default to IPV4, got {original_ip_type!r}"

    code, message = _error(lambda: tf.update_server(ServerId=server_id, IpAddressType="DUALSTACK"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected_message = "Server must be OFFLINE to change IpAddressType"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: IpAddressType did not change while the server was online
    unchanged = tf.describe_server(ServerId=server_id)["Server"].get("IpAddressType", "IPV4")
    assert unchanged == original_ip_type, (
        f"IpAddressType changed despite the rejected UpdateServer call, got {unchanged!r}"
    )

    # Positive control: the identical call succeeds once the server is stopped.
    tf.stop_server(ServerId=server_id)
    _poll_until(
        lambda: tf.describe_server(ServerId=server_id)["Server"]["State"],
        lambda s: s == "OFFLINE",
        timeout_s=240.0,
        interval_s=10.0,
    )
    tf.update_server(ServerId=server_id, IpAddressType="DUALSTACK")
    updated = tf.describe_server(ServerId=server_id)["Server"].get("IpAddressType")
    assert updated == "DUALSTACK", (
        f"UpdateServer(IpAddressType=DUALSTACK) did not persist while OFFLINE, got {updated!r}"
    )


def _safe_delete_server(tf, server_id: str) -> None:
    try:
        tf.delete_server(ServerId=server_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
