"""close-tunnel-delete-flag-removes-tunnel-metadata."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "close-tunnel-delete-flag-removes-tunnel-metadata"
GROUP = "state-machine"
SERVICES = ["iotsecuretunneling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloseTunnel(delete=True) deletes tunnel metadata immediately; delete=False keeps it describable."""
    client = ctx.client("iotsecuretunneling")

    # Control: closed WITHOUT delete stays visible via DescribeTunnel.
    kept = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-keep-"))
    kept_id = kept["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=kept_id, delete=True))
    client.close_tunnel(tunnelId=kept_id)
    kept_described = _poll_until(
        lambda: client.describe_tunnel(tunnelId=kept_id)["tunnel"],
        lambda t: t["status"] == "CLOSED",
        timeout_s=30.0,
    )
    assert kept_described["status"] == "CLOSED"

    # Break: closed WITH delete=True must disappear from DescribeTunnel.
    deleted = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-del-"))
    deleted_id = deleted["tunnelId"]
    client.close_tunnel(tunnelId=deleted_id, delete=True)

    expected_message = f"Tunnel {deleted_id} does not exist."
    code, message = _poll_until(
        lambda: _describe_outcome(client, deleted_id),
        lambda outcome: outcome[0] != _DESCRIBED,
        timeout_s=30.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Deletion removed the record, not just hidden it from reads: a mutation on the
    # dead id fails the same way a read does.
    rotate_code, rotate_message = _error(
        lambda: client.rotate_tunnel_access_token(tunnelId=deleted_id, clientMode="SOURCE")
    )
    assert rotate_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {rotate_code!r}"
    assert rotate_message == expected_message, f"expected message {expected_message!r}, got {rotate_message!r}"

    # Positive control still holds: the kept tunnel is still describable after the deletion above.
    still_there = client.describe_tunnel(tunnelId=kept_id)["tunnel"]
    assert still_there["status"] == "CLOSED"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


_DESCRIBED = "<described>"


def _describe_outcome(client, tunnel_id):
    """DescribeTunnel outcome: (_DESCRIBED, status) while the tunnel is readable, else the
    botocore (code, message). _DESCRIBED is not a value any error code can equal."""
    from botocore.exceptions import ClientError

    try:
        return _DESCRIBED, client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]["status"]
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
