"""rotate-all-mode-reissues-both-tokens."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "rotate-all-mode-reissues-both-tokens"
GROUP = "state-machine"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RotateTunnelAccessToken(clientMode=ALL) returns new, distinct source and destination tokens; both pre-rotation
    tokens, which connected before, then fail the WebSocket handshake while both connection states stay
    DISCONNECTED, and the new tokens reach CONNECTED."""
    import websocket  # noqa: F401

    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(description=ctx.unique_name("sim2real-iot-tunnel-rotate-all-"))
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))
    old_source_token = opened["sourceAccessToken"]
    old_destination_token = opened["destinationAccessToken"]

    # Positive control: both pre-rotation tokens are live credentials that can connect. Their
    # connect latency also calibrates how long we must hold absence for below.
    source_connect_latency_s = _connect_and_wait(
        ctx, client, tunnel_id, old_source_token, "source", "sourceConnectionState"
    )
    destination_connect_latency_s = _connect_and_wait(
        ctx, client, tunnel_id, old_destination_token, "destination", "destinationConnectionState"
    )

    rotated = client.rotate_tunnel_access_token(tunnelId=tunnel_id, clientMode="ALL")
    new_source_token = rotated["sourceAccessToken"]
    new_destination_token = rotated["destinationAccessToken"]

    assert new_source_token != old_source_token, (
        f"ALL-mode rotation did not reissue the source token: {new_source_token!r} == {old_source_token!r}"
    )
    assert new_destination_token != old_destination_token, (
        "ALL-mode rotation did not reissue the destination token: "
        f"{new_destination_token!r} == {old_destination_token!r}"
    )
    assert new_source_token != new_destination_token, (
        f"reissued source and destination tokens collide: {new_source_token!r}"
    )

    # Break: the pre-rotation tokens must no longer establish a connection.
    old_source_failed = False
    try:
        _ws_connect(ctx, ctx.region, old_source_token, "source").close()
    except Exception:
        old_source_failed = True
    assert old_source_failed, "the pre-rotation source access token still connects after ALL-mode rotation"

    old_destination_failed = False
    try:
        _ws_connect(ctx, ctx.region, old_destination_token, "destination").close()
    except Exception:
        old_destination_failed = True
    assert old_destination_failed, (
        "the pre-rotation destination access token still connects after ALL-mode rotation"
    )

    # Effect absent: neither rejected reconnect attempt resulted in a connection. Hold the window at
    # >= 3x the measured connect latency instead of trusting a bare sleep, and keep sampling so a
    # late transition cannot slip through between one read and the next.
    hold_s = max(3.0, 3.0 * max(source_connect_latency_s, destination_connect_latency_s))
    _hold_while(
        lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
        lambda t: t["sourceConnectionState"]["status"] == "DISCONNECTED"
        and t["destinationConnectionState"]["status"] == "DISCONNECTED",
        lambda t: (
            "expected both connection states to stay DISCONNECTED after the rejected "
            f"reconnects, got source={t['sourceConnectionState']['status']!r} "
            f"destination={t['destinationConnectionState']['status']!r}"
        ),
        duration_s=hold_s,
    )

    # Restore/terminal: the reissued tokens are the ones that actually connect, proven via
    # DescribeTunnel -- an independent read through a different operation than the rotate.
    _connect_and_wait(ctx, client, tunnel_id, new_source_token, "source", "sourceConnectionState")
    _connect_and_wait(
        ctx, client, tunnel_id, new_destination_token, "destination", "destinationConnectionState"
    )


def _connect_and_wait(ctx, client, tunnel_id, token, mode, state_key):
    """Connect, wait for CONNECTED, disconnect, wait for DISCONNECTED. Returns the connect latency."""
    start = time.monotonic()
    ws = _ws_connect(ctx, ctx.region, token, mode)
    try:
        _poll_until(
            lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
            lambda t: t[state_key]["status"] == "CONNECTED",
            timeout_s=30.0,
        )
    finally:
        ws.close()
    latency_s = time.monotonic() - start
    _poll_until(
        lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
        lambda t: t[state_key]["status"] == "DISCONNECTED",
        timeout_s=30.0,
    )
    return latency_s


def _hold_while(probe, predicate, message, *, duration_s, interval_s=1.0):
    """Bounded window (B5 calibrated window): sample on a deadline, never a bare sleep."""
    deadline = time.monotonic() + duration_s
    while True:
        value = probe()
        assert predicate(value), message(value)
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)


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
