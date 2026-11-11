"""rotate-access-token-on-closed-tunnel-rejected."""
from __future__ import annotations

import time

CHECK = "rotate-access-token-on-closed-tunnel-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsecuretunneling"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RotateTunnelAccessToken on a CLOSED tunnel is rejected; an OPEN sibling tunnel still rotates fine."""
    client = ctx.client("iotsecuretunneling")

    # Positive control: rotating on an OPEN tunnel succeeds.
    control = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-open-"),
        tags=[{"key": "env", "value": "sim2real"}],
    )
    control_id = control["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=control_id, delete=True))
    control_rotated = client.rotate_tunnel_access_token(tunnelId=control_id, clientMode="SOURCE")
    assert control_rotated["sourceAccessToken"] != control["sourceAccessToken"], (
        f"expected rotation to reissue sourceAccessToken, got same token {control['sourceAccessToken']!r}"
    )

    # Break: close a tunnel, then try to rotate its tokens.
    closed = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-closed-"),
        tags=[{"key": "env", "value": "sim2real"}],
    )
    closed_id = closed["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=closed_id, delete=True))
    client.close_tunnel(tunnelId=closed_id)
    _poll_until(
        lambda: client.describe_tunnel(tunnelId=closed_id)["tunnel"],
        lambda t: t["status"] == "CLOSED",
        timeout_s=30.0,
    )

    code, message = _error(lambda: client.rotate_tunnel_access_token(tunnelId=closed_id, clientMode="SOURCE"))
    # Empirically, real AWS rejects rotation on a CLOSED tunnel with ValidationException
    # (not ResourceNotFoundException — the tunnelId still resolves to a recently-closed
    # tunnel record during the post-close retention window, but rotation is disallowed).
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = f"Tunnel {closed_id} is close."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the tunnel remains CLOSED, not reopened by the rejected rotate call.
    still_closed = client.describe_tunnel(tunnelId=closed_id)["tunnel"]
    assert still_closed["status"] == "CLOSED", f"expected status CLOSED, got {still_closed['status']!r}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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
