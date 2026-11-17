"""native-send-message-websocket-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "native-send-message-websocket-round-trip"
GROUP = "data-plane"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A client on the IVS Chat WebSocket that sends SEND_MESSAGE receives its own MESSAGE frame back with
    the exact content, its user id as sender and a 12-character message id."""
    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(
        name=ctx.unique_name("sim2real-ivschat-room"), tags={"sim2real": CHECK}
    )
    room_arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=room_arn))

    user_id = "sim2real-native-sender"
    token = ivschat.create_chat_token(
        roomIdentifier=room_arn, userId=user_id, capabilities=["SEND_MESSAGE"]
    )["token"]

    ws = _ws_connect(ctx, token)
    ctx.on_cleanup(ws.close)

    ws.send(json.dumps({"Action": "SEND_MESSAGE", "Content": "hello-sim2real", "RequestId": "req-1"}))
    msg = _ws_recv_until(ws, lambda m: m.get("RequestId") == "req-1", timeout_s=20.0)

    assert msg["Type"] == "MESSAGE", f"expected a MESSAGE frame, got {msg.get('Type')!r}: {msg}"
    assert msg["Content"] == "hello-sim2real", (
        f"expected Content 'hello-sim2real', got {msg['Content']!r}"
    )
    assert msg["Sender"]["UserId"] == user_id, (
        f"expected Sender.UserId {user_id!r}, got {msg['Sender']['UserId']!r}"
    )
    assert isinstance(msg["Id"], str) and len(msg["Id"]) == 12, (
        f"expected a 12-char string message Id, got {msg['Id']!r}"
    )


def _ws_connect(ctx, token):
    import websocket
    endpoint = ctx.service_url(f"wss://edge.ivschat.{ctx.region}.amazonaws.com")
    return websocket.create_connection(endpoint, subprotocols=[token], timeout=20)


def _ws_recv_until(ws, predicate, timeout_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(0.5, deadline - time.monotonic())
        ws.settimeout(remaining)
        try:
            raw = ws.recv()
        except Exception:
            break
        if not raw:
            break
        try:
            msg = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if predicate(msg):
            return msg
    raise AssertionError("expected websocket message not received within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
