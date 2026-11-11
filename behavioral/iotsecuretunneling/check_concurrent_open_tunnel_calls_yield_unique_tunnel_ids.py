"""concurrent-open-tunnel-calls-yield-unique-tunnel-ids."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-open-tunnel-calls-yield-unique-tunnel-ids"
GROUP = "concurrency"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent OpenTunnel calls each succeed and get distinct tunnelId/ARN/access tokens."""
    client = ctx.client("iotsecuretunneling")
    n = 8

    def _open(i):
        return client.open_tunnel(
            description=ctx.unique_name(f"sim2real-iot-tunnel-race-{i}-"),
            tags=[{"key": "sim2real-check", "value": CHECK}],
        )

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_open, range(n)))

    for r in results:
        ctx.on_cleanup(lambda tid=r["tunnelId"]: client.close_tunnel(tunnelId=tid, delete=True))

    tunnel_ids = [r["tunnelId"] for r in results]
    tunnel_arns = [r["tunnelArn"] for r in results]
    source_tokens = [r["sourceAccessToken"] for r in results]
    destination_tokens = [r["destinationAccessToken"] for r in results]

    assert len(set(tunnel_ids)) == n, "concurrent OpenTunnel calls collided on tunnelId"
    assert len(set(tunnel_arns)) == n, "concurrent OpenTunnel calls collided on tunnelArn"
    assert len(set(source_tokens)) == n, "concurrent OpenTunnel calls collided on sourceAccessToken"
    assert len(set(destination_tokens)) == n, "concurrent OpenTunnel calls collided on destinationAccessToken"

    for tunnel_id in tunnel_ids:
        described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
        assert described["status"] == "OPEN", (
            f"tunnel {tunnel_id} expected status OPEN, got {described['status']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
