"""native-delete-message-triggers-delete-event."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "native-delete-message-triggers-delete-event"
GROUP = "data-plane"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteMessage on a message sent over the WebSocket pushes an aws:DELETE_MESSAGE event to connected
    clients carrying the deleted message's id and the id DeleteMessage returned."""
    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(
        name=ctx.unique_name("sim2real-ivschat-room"), tags={"sim2real": CHECK}
    )
    room_arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=room_arn))

    user_id = "sim2real-native-poster"
    token = ivschat.create_chat_token(
        roomIdentifier=room_arn, userId=user_id, capabilities=["SEND_MESSAGE"]
    )["token"]
    ws = _ws_connect(ctx, token)
    ctx.on_cleanup(ws.close)

    ws.send(json.dumps({"Action": "SEND_MESSAGE", "Content": "delete-me", "RequestId": "req-del"}))
    sent = _ws_recv_until(ws, lambda m: m.get("RequestId") == "req-del", timeout_s=20.0)
    message_id = sent["Id"]

    delete_resp = ivschat.delete_message(
        roomIdentifier=room_arn, id=message_id, reason="sim2real-test"
    )
    delete_op_id = delete_resp["id"]

    evt = _ws_recv_until(
        ws, lambda m: m.get("Type") == "EVENT" and m.get("EventName") == "aws:DELETE_MESSAGE",
        timeout_s=20.0,
    )
    assert evt["Attributes"]["MessageId"] == message_id, (
        f"expected DELETE_MESSAGE event to carry the deleted message's id "
        f"{message_id!r}, got Attributes={evt.get('Attributes')!r}"
    )
    assert evt["Id"] == delete_op_id, (
        f"expected DELETE_MESSAGE event Id to match DeleteMessage's own reported "
        f"operation id {delete_op_id!r}, got {evt.get('Id')!r}"
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
