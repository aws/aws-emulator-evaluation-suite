"""close-tunnel-disconnects-active-websocket-connections."""
from __future__ import annotations

import time

CHECK = "close-tunnel-disconnects-active-websocket-connections"
GROUP = "native-protocol"
SERVICES = ["iotsecuretunneling"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CloseTunnel sends a connected source local proxy the in-band tunnel-protocol termination frame (type 5, no
    streamId) over the data-plane socket, and the source connection state ends DISCONNECTED."""
    import websocket  # noqa: F401 - availability probe; re-imported at use

    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-closeforce-"),
        tags=[{"key": "purpose", "value": "sim2real-close-tunnel-websocket"}],
    )
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    source_ws = _ws_connect(ctx, ctx.region, opened["sourceAccessToken"], "source")
    try:
        _poll_until(
            lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
            lambda t: t["sourceConnectionState"]["status"] == "CONNECTED",
            timeout_s=30.0,
        )

        client.close_tunnel(tunnelId=tunnel_id)

        _poll_until(
            lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
            lambda t: t["status"] == "CLOSED",
            timeout_s=30.0,
        )

        received_termination_signal, seen_frames = _wait_for_termination_signal(source_ws, timeout_s=30.0)
        assert received_termination_signal, (
            "local proxy WebSocket received no in-band termination signal (and stayed open) after "
            f"CloseTunnel; frames observed: {seen_frames!r}"
        )

        final = client.describe_tunnel(tunnelId=tunnel_id)["tunnel"]
        assert final["sourceConnectionState"]["status"] == "DISCONNECTED", (
            f"expected sourceConnectionState DISCONNECTED after CloseTunnel, "
            f"got {final['sourceConnectionState']['status']!r}"
        )
    finally:
        try:
            source_ws.close()
        except Exception:
            pass


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


# Tunnel-protocol messages are a 2-byte big-endian length prefix followed by a protobuf-tag body;
# field 1 (tag byte 0x08, varint wire type) carries the message type. Measured via real-AWS replay
# (subprotocol aws.iot.securetunneling-3.0): CloseTunnel makes the server send exactly one such
# frame, body b"\x08\x05" (type 5, no streamId), to the connected local proxy.
_TUNNEL_MSG_TYPE_TAG = 0x08
_TUNNEL_MSG_TYPE_SESSION_TERMINATED = 5


def _is_session_termination_frame(frame_bytes):
    if len(frame_bytes) < 4:
        return False
    length = int.from_bytes(frame_bytes[:2], "big")
    body = frame_bytes[2 : 2 + length]
    return len(body) >= 2 and body[0] == _TUNNEL_MSG_TYPE_TAG and body[1] == _TUNNEL_MSG_TYPE_SESSION_TERMINATED


def _wait_for_termination_signal(ws, timeout_s=30.0):
    import websocket

    seen = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        ws.settimeout(max(0.1, remaining))
        try:
            opcode, data = ws.recv_data()
        except (
            websocket.WebSocketConnectionClosedException,
            websocket.WebSocketTimeoutException,
            ConnectionError,
            OSError,
        ) as exc:
            if isinstance(exc, websocket.WebSocketTimeoutException):
                continue
            return True, seen  # the transport itself was severed -- also a valid termination
        data = bytes(data)
        seen.append((opcode, data[:32]))
        if opcode == websocket.ABNF.OPCODE_CLOSE:
            return True, seen
        if opcode == websocket.ABNF.OPCODE_BINARY and _is_session_termination_frame(data):
            return True, seen
    return False, seen


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
