"""custom-timeout-config-persisted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-timeout-config-persisted"
GROUP = "config-persistence"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom maxLifetimeTimeoutMinutes supplied to OpenTunnel is persisted verbatim."""
    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-"),
        timeoutConfig={"maxLifetimeTimeoutMinutes": 30},
    )
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    actual = described["timeoutConfig"]["maxLifetimeTimeoutMinutes"]
    assert actual == 30, f"expected the custom maxLifetimeTimeoutMinutes=30 to persist, got {actual}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
