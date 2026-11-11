"""close-tunnel-transitions-status-to-closed."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "close-tunnel-transitions-status-to-closed"
GROUP = "state-machine"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloseTunnel (without delete) moves an OPEN tunnel to CLOSED while it remains describable."""
    client = ctx.client("iotsecuretunneling")
    resp = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-"))
    tunnel_id = resp["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    described = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
    assert described["status"] == "OPEN", f"expected freshly opened tunnel status OPEN, got {described['status']!r}"

    client.close_tunnel(tunnelId=tunnel_id)

    final = _poll_until(
        lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
        lambda t: t["status"] == "CLOSED",
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert final["status"] == "CLOSED", f"expected tunnel {tunnel_id} status CLOSED after CloseTunnel, got {final['status']!r}"
    assert final["tunnelId"] == tunnel_id, f"expected DescribeTunnel to echo tunnelId {tunnel_id!r}, got {final['tunnelId']!r}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
