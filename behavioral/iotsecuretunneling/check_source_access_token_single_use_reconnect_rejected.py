"""source-access-token-single-use-reconnect-rejected."""
from __future__ import annotations

import time

CHECK = "source-access-token-single-use-reconnect-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsecuretunneling"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A client access token connects to a tunnel once: reconnecting with the spent source token fails the
    handshake and leaves the source DISCONNECTED, while a freshly rotated token differs and connects."""
    import websocket  # noqa: F401

    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-single-use-"),
        tags=[{"key": "purpose", "value": "sim2real-source-access-token-single-use"}],
    )
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))
    spent_token = opened["sourceAccessToken"]

    connect_started = time.monotonic()
    first_ws = _ws_connect(ctx, ctx.region, spent_token, "source")
    _poll_until(
        lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
        lambda t: t["sourceConnectionState"]["status"] == "CONNECTED",
        timeout_s=30.0,
    )
    connect_latency_s = time.monotonic() - connect_started
    first_ws.close()
    _poll_until(
        lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
        lambda t: t["sourceConnectionState"]["status"] == "DISCONNECTED",
        timeout_s=30.0,
    )

    # Break: reconnect with the same (already-used) token.
    reused_ws = None
    handshake_failed = False
    try:
        reused_ws = _ws_connect(ctx, ctx.region, spent_token, "source")
    except Exception:
        handshake_failed = True
    else:
        try:
            reused_ws.close()
        except Exception:
            pass
    assert handshake_failed, "reconnecting with an already-used client access token was accepted"

    # Effect absent: no new CONNECTED transition results from the rejected reconnect. The window
    # is calibrated to the measured legitimate-connect latency (never a bare sleep) and polled
    # throughout so a late transition is caught, not just the value at one arbitrary instant.
    unaffected = _hold_absent(
        lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]["sourceConnectionState"]["status"],
        forbidden="CONNECTED",
        window_s=max(3.0 * connect_latency_s, 3.0),
    )
    assert unaffected == "DISCONNECTED", (
        f"sourceConnectionState after rejected reconnect = {unaffected!r}, want 'DISCONNECTED'"
    )

    # Positive control: a freshly rotated token connects successfully.
    rotated = client.rotate_tunnel_access_token(tunnelId=tunnel_id, clientMode="SOURCE")
    fresh_token = rotated["sourceAccessToken"]
    assert fresh_token != spent_token
    fresh_ws = _ws_connect(ctx, ctx.region, fresh_token, "source")
    try:
        _poll_until(
            lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
            lambda t: t["sourceConnectionState"]["status"] == "CONNECTED",
            timeout_s=30.0,
        )
    finally:
        fresh_ws.close()


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


def _hold_absent(probe, *, forbidden, window_s, interval_s=0.5):
    deadline = time.monotonic() + window_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        assert last != forbidden, (
            f"observed {last!r} inside the {window_s:.1f}s absence window; the rejected call "
            f"must never advance the connection state to {forbidden!r}"
        )
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
