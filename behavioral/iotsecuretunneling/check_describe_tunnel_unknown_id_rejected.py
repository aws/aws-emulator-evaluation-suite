"""describe-tunnel-unknown-id-rejected."""
from __future__ import annotations

CHECK = "describe-tunnel-unknown-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsecuretunneling"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTunnel on a tunnelId that was never created is rejected with ResourceNotFoundException."""
    client = ctx.client("iotsecuretunneling")

    bogus_id = ctx.unique_name("sim2real-nonexistent-tunnel-")
    code, message = _error(lambda: client.describe_tunnel(tunnelId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for never-created tunnelId, got {code}"
    expected_message = f"Tunnel {bogus_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a real tunnel is still describable.
    opened = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-"))
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))
    described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    assert described["tunnelId"] == tunnel_id, f"expected describe_tunnel to return tunnelId={tunnel_id}, got {described['tunnelId']}"


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
