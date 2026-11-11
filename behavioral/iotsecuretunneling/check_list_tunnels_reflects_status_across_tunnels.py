"""list-tunnels-reflects-status-across-tunnels."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-tunnels-reflects-status-across-tunnels"
GROUP = "state-machine"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTunnels reports the correct current status for both OPEN and CLOSED tunnels."""
    client = ctx.client("iotsecuretunneling")

    open_resp = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-open-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    open_id = open_resp["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=open_id, delete=True))

    closed_resp = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-closed-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    closed_id = closed_resp["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=closed_id, delete=True))
    client.close_tunnel(tunnelId=closed_id)
    _poll_until(
        lambda: client.describe_tunnel(tunnelId=closed_id)["tunnel"],
        lambda t: t["status"] == "CLOSED",
        timeout_s=30.0,
    )

    def _list_all():
        by_id = {}
        next_token = None
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            page = client.list_tunnels(**kwargs)
            for summary in page.get("tunnelSummaries", []):
                by_id[summary["tunnelId"]] = summary
            next_token = page.get("nextToken")
            if not next_token:
                break
        return by_id

    by_id = _poll_until(
        _list_all,
        lambda d: open_id in d and closed_id in d,
        timeout_s=30.0,
    )

    assert by_id[open_id]["status"] == "OPEN", (
        f"ListTunnels expected {open_id} status OPEN, got {by_id[open_id]['status']!r}"
    )
    assert by_id[closed_id]["status"] == "CLOSED", (
        f"ListTunnels expected {closed_id} status CLOSED, got {by_id[closed_id]['status']!r}"
    )


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
