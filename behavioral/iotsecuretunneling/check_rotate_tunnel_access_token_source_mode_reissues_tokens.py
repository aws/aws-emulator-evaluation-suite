"""rotate-tunnel-access-token-source-mode-reissues-tokens."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rotate-tunnel-access-token-source-mode-reissues-tokens"
GROUP = "state-machine"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RotateTunnelAccessToken(clientMode=SOURCE) returns the tunnel's ARN and a new sourceAccessToken and omits
    destinationAccessToken, unlike clientMode=ALL, which reissues it; the tunnel stays OPEN."""
    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-"))
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    original_source_token = opened["sourceAccessToken"]
    original_destination_token = opened["destinationAccessToken"]

    rotated = client.rotate_tunnel_access_token(tunnelId=tunnel_id, clientMode="SOURCE")

    assert rotated["tunnelArn"] == opened["tunnelArn"], (
        f"expected tunnelArn {opened['tunnelArn']!r}, got {rotated['tunnelArn']!r}"
    )
    assert rotated["sourceAccessToken"] != original_source_token, (
        "expected a fresh sourceAccessToken, got the pre-rotation value back"
    )
    assert rotated["sourceAccessToken"], "expected a non-empty sourceAccessToken"
    assert "destinationAccessToken" not in rotated, (
        f"clientMode=SOURCE must not reissue destinationAccessToken, but the response included "
        f"{rotated.get('destinationAccessToken')!r}"
    )

    # Positive control on the sibling mode: ALL does reissue the destination token, so the
    # absence above is SOURCE-scoped behavior, not a target that never rotates the destination.
    all_rotated = client.rotate_tunnel_access_token(tunnelId=tunnel_id, clientMode="ALL")
    assert all_rotated["destinationAccessToken"] != original_destination_token, (
        "expected clientMode=ALL to reissue destinationAccessToken on the same tunnel"
    )

    described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    assert described["status"] == "OPEN", f"expected tunnel status OPEN, got {described['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
