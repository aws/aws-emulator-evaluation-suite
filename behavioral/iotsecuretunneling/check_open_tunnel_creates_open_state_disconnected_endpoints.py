"""open-tunnel-creates-open-state-disconnected-endpoints."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "open-tunnel-creates-open-state-disconnected-endpoints"
GROUP = "state-machine"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OpenTunnel starts a tunnel in OPEN status with both endpoints DISCONNECTED."""
    client = ctx.client("iotsecuretunneling")
    resp = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-"),
        tags=[{"key": "sim2real-check", "value": "open-tunnel-creates-open-state-disconnected-endpoints"}],
    )
    tunnel_id = resp["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    assert resp["tunnelArn"].endswith(tunnel_id), (
        f"expected tunnelArn to end with tunnelId {tunnel_id!r}, got {resp['tunnelArn']!r}"
    )
    assert resp["sourceAccessToken"] and resp["destinationAccessToken"], (
        f"expected both access tokens non-empty, got source={resp.get('sourceAccessToken')!r} "
        f"destination={resp.get('destinationAccessToken')!r}"
    )
    assert resp["sourceAccessToken"] != resp["destinationAccessToken"], (
        "expected source and destination access tokens to differ, but OpenTunnel returned "
        f"the identical token {resp['sourceAccessToken']!r} for both"
    )

    described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    assert described["tunnelId"] == tunnel_id, (
        f"expected DescribeTunnel to return tunnelId {tunnel_id!r}, got {described['tunnelId']!r}"
    )
    assert described["status"] == "OPEN", (
        f"expected a freshly opened tunnel to have status OPEN, got {described['status']!r}"
    )
    assert described["sourceConnectionState"]["status"] == "DISCONNECTED", (
        "expected source connection state DISCONNECTED before any client connects, got "
        f"{described['sourceConnectionState']['status']!r}"
    )
    assert described["destinationConnectionState"]["status"] == "DISCONNECTED", (
        "expected destination connection state DISCONNECTED before any client connects, got "
        f"{described['destinationConnectionState']['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
