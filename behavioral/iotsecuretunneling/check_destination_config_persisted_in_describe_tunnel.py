"""destination-config-persisted-in-describe-tunnel."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "destination-config-persisted-in-describe-tunnel"
GROUP = "config-persistence"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """destinationConfig.services supplied to OpenTunnel is echoed back unchanged by DescribeTunnel."""
    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-"),
        destinationConfig={"services": ["SSH", "HTTP1"]},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    services = described["destinationConfig"]["services"]
    assert services == ["SSH", "HTTP1"], f"expected echoed services ['SSH', 'HTTP1'], got {services!r}"
    assert "thingName" not in described["destinationConfig"], (
        f"expected no thingName in destinationConfig when none was supplied, got {described['destinationConfig']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
