"""native-local-proxy-stream-relay-round-trip."""
from __future__ import annotations

import time

CHECK = "native-local-proxy-stream-relay-round-trip"
GROUP = "native-protocol"
SERVICES = ["iotsecuretunneling"]

from behavioral_harness import tags


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Source and destination local-proxy WebSocket clients connect to a tunnel and the service relays a
    STREAM_START and a DATA frame end to end with the same streamId and payload."""
    import websocket  # noqa: F401 - availability probe; re-imported at use

    client = ctx.client("iotsecuretunneling")
    opened = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-relay-"),
        tags=[{"key": "purpose", "value": "sim2real-native-relay"}],
    )
    tunnel_id = opened["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=tunnel_id, delete=True))

    source_ws = None
    destination_ws = None
    try:
        source_ws = _ws_connect(ctx, ctx.region, opened["sourceAccessToken"], "source")
        _poll_until(
            lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
            lambda t: t["sourceConnectionState"]["status"] == "CONNECTED",
            timeout_s=30.0,
        )

        destination_ws = _ws_connect(ctx, ctx.region, opened["destinationAccessToken"], "destination")
        _poll_until(
            lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
            lambda t: t["destinationConnectionState"]["status"] == "CONNECTED",
            timeout_s=30.0,
        )

        stream_id = 1
        source_ws.send_binary(_encode_tunnel_message(_MSG_STREAM_START, stream_id))

        dest_reader = _FrameReader(destination_ws)
        start_msg = dest_reader.read_message(timeout_s=30.0, skip_types=(_MSG_SERVICE_IDS,))
        assert start_msg["type"] == _MSG_STREAM_START, (
            f"expected the destination local proxy to receive a STREAM_START frame "
            f"(type={_MSG_STREAM_START}) relayed from the source, got type={start_msg['type']!r}"
        )
        assert start_msg["streamId"] == stream_id, (
            f"expected the relayed STREAM_START frame to carry streamId={stream_id}, "
            f"got streamId={start_msg['streamId']!r}"
        )

        payload = b"sim2real-secure-tunnel-echo"
        destination_ws.send_binary(_encode_tunnel_message(_MSG_DATA, stream_id, payload=payload))

        source_reader = _FrameReader(source_ws)
        data_msg = source_reader.read_message(timeout_s=30.0, skip_types=(_MSG_SERVICE_IDS,))
        assert data_msg["type"] == _MSG_DATA, (
            f"expected the source local proxy to receive a DATA frame (type={_MSG_DATA}) relayed "
            f"from the destination, got type={data_msg['type']!r}"
        )
        assert data_msg["streamId"] == stream_id, (
            f"expected the relayed DATA frame to carry streamId={stream_id}, "
            f"got streamId={data_msg['streamId']!r}"
        )
        assert data_msg["payload"] == payload, (
            f"expected the relayed DATA frame's payload to be the exact bytes sent by the "
            f"destination local proxy ({payload!r}), got {data_msg['payload']!r}"
        )
    finally:
        for ws in (source_ws, destination_ws):
            if ws is not None:
                try:
                    ws.close()
                except Exception:
                    pass

    _poll_until(
        lambda: client.describe_tunnel(tunnelId=tunnel_id)["tunnel"],
        lambda t: t["sourceConnectionState"]["status"] == "DISCONNECTED"
        and t["destinationConnectionState"]["status"] == "DISCONNECTED",
        timeout_s=30.0,
    )


_MSG_UNKNOWN = 0
_MSG_DATA = 1
_MSG_STREAM_START = 2
_MSG_STREAM_RESET = 3
_MSG_SESSION_RESET = 4
# Observed on a real replay: each local-proxy WebSocket connection receives a SERVICE_IDS
# control frame immediately on connect, ahead of any relayed stream frame; both readers below
# must skip it rather than treat the first frame as the relay under test.
_MSG_SERVICE_IDS = 5


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


def _varint_encode(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _varint_decode(buf, i):
    result = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7


def _encode_tunnel_message(msg_type, stream_id, payload=None):
    body = bytearray()
    body += b"\x08" + _varint_encode(msg_type)
    body += b"\x10" + _varint_encode(stream_id)
    if payload is not None:
        body += b"\x22" + _varint_encode(len(payload)) + payload
    return len(body).to_bytes(2, "big") + bytes(body)


def _decode_tunnel_message(body):
    i = 0
    n = len(body)
    out = {"type": None, "streamId": None, "payload": None}
    while i < n:
        tag, i = _varint_decode(body, i)
        field, wire_type = tag >> 3, tag & 0x7
        if wire_type == 0:
            val, i = _varint_decode(body, i)
            if field == 1:
                out["type"] = val
            elif field == 2:
                out["streamId"] = val
        elif wire_type == 2:
            length, i = _varint_decode(body, i)
            data = bytes(body[i : i + length])
            i += length
            if field == 4:
                out["payload"] = data
        else:
            break
    return out


class _FrameReader:
    """Buffers WebSocket binary frames and yields whole 2-byte-length-prefixed tunnel messages."""

    def __init__(self, ws):
        self.ws = ws
        self.buf = bytearray()

    def read_message(self, timeout_s=20.0, *, skip_types=()):
        import websocket

        deadline = time.monotonic() + timeout_s
        while True:
            if len(self.buf) >= 2:
                length = int.from_bytes(bytes(self.buf[:2]), "big")
                if len(self.buf) >= 2 + length:
                    body = bytes(self.buf[2 : 2 + length])
                    del self.buf[: 2 + length]
                    msg = _decode_tunnel_message(body)
                    if msg["type"] in skip_types:
                        continue
                    return msg
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("timed out waiting for a secure-tunneling protocol frame")
            self.ws.settimeout(max(0.1, remaining))
            opcode, data = self.ws.recv_data()
            if opcode == websocket.ABNF.OPCODE_BINARY:
                self.buf.extend(data)
            elif opcode == websocket.ABNF.OPCODE_CLOSE:
                raise AssertionError("websocket closed while waiting for a secure-tunneling protocol frame")


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
