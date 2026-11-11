"""default-timeout-config-is-720-minutes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "default-timeout-config-is-720-minutes"
GROUP = "config-persistence"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OpenTunnel without a timeoutConfig defaults maxLifetimeTimeoutMinutes to 720 (12 hours)."""
    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-"),
        tags=[{"key": "purpose", "value": "sim2real-default-timeout"}],
    )
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    actual = described["timeoutConfig"]["maxLifetimeTimeoutMinutes"]
    assert actual == 720, f"expected default maxLifetimeTimeoutMinutes=720, got {actual}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
