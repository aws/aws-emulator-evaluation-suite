"""rotate-with-destination-config-and-source-mode-rejected."""
from __future__ import annotations

CHECK = "rotate-with-destination-config-and-source-mode-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsecuretunneling"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RotateTunnelAccessToken with a destinationConfig and clientMode=SOURCE fails ValidationException with the
    exact message and leaves the tunnel OPEN; the same rotation without destinationConfig issues a new token."""
    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-"),
        tags=[{"key": "purpose", "value": "sim2real-rotate-destconfig-source-rejected"}],
    )
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    code, message = _error(
        lambda: client.rotate_tunnel_access_token(
            tunnelId=tunnel_id,
            clientMode="SOURCE",
            destinationConfig={"services": ["SSH"]},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "DestinationConfig is not allowed with clientMode SOURCE"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected request left the tunnel's lifecycle state untouched.
    unaffected = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    assert unaffected["status"] == "OPEN", f"expected OPEN, got {unaffected['status']!r}"

    # Positive control: the same rotate call, without the illegal destinationConfig, succeeds.
    rotated = client.rotate_tunnel_access_token(tunnelId=tunnel_id, clientMode="SOURCE")
    assert rotated["sourceAccessToken"] != opened["sourceAccessToken"], (
        "expected a freshly-issued sourceAccessToken, got the same token back"
    )

    # Terminal read: an independent describe_tunnel confirms the restored call left the
    # tunnel OPEN rather than the rejected call having any lingering effect.
    restored = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    assert restored["status"] == "OPEN", f"expected OPEN after successful rotate, got {restored['status']!r}"


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
