"""access-token-mode-mismatch-rejected."""
from __future__ import annotations

import time

CHECK = "access-token-mode-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsecuretunneling"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A destinationAccessToken used for a local-proxy-mode=source WebSocket connection fails the handshake and
    leaves sourceConnectionState DISCONNECTED, while the sourceAccessToken in source mode reaches CONNECTED."""
    import websocket  # noqa: F401

    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-mismatch-"),
        tags=[{"key": "sim2real", "value": "access-token-mode-mismatch-rejected"}],
    )
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    # Break: connect with the DESTINATION token under local-proxy-mode=source.
    mismatched_ws = None
    handshake_failed = False
    try:
        mismatched_ws = _ws_connect(ctx, ctx.region, opened["destinationAccessToken"], "source")
    except Exception:
        handshake_failed = True
    else:
        try:
            mismatched_ws.close()
        except Exception:
            pass
    assert handshake_failed, "connecting with a mismatched token/mode pair was unexpectedly accepted"

    # Effect absent: sourceConnectionState never flips to CONNECTED from the rejected attempt.
    # Freeze detector: repeated independent reads, spaced out, must all agree on DISCONNECTED.
    for i in range(3):
        time.sleep(1.0)
        unaffected = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
        status = unaffected["sourceConnectionState"]["status"]
        assert status == "DISCONNECTED", (
            f"expected sourceConnectionState to remain DISCONNECTED after the rejected "
            f"mismatched-token handshake, got {status!r} on read {i + 1}/3"
        )

    # Positive control: the correctly-paired source token/mode combination connects fine.
    source_ws = _ws_connect(ctx, ctx.region, opened["sourceAccessToken"], "source")
    try:
        _poll_until(
            lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
            lambda t: t["sourceConnectionState"]["status"] == "CONNECTED",
            timeout_s=30.0,
        )
    finally:
        source_ws.close()


def _ws_connect(ctx, region, token, mode, timeout_s=15.0):
    import websocket

    host = f"data.tunneling.iot.{region}.amazonaws.com"
    url = ctx.service_url(f"wss://{host}") + f"/tunnel?local-proxy-mode={mode}"
    return websocket.create_connection(
        url,
        header=[f"access-token: {token}"],
        subprotocols=["aws.iot.securetunneling-3.0", "aws.iot.securetunneling-2.0"],
        timeout=timeout_s,
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
