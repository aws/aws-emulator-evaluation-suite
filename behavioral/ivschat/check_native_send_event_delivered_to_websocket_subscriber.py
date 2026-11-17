"""native-send-event-delivered-to-websocket-subscriber."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "native-send-event-delivered-to-websocket-subscriber"
GROUP = "data-plane"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEvent (a control-plane/application HTTP call) is fanned out live to every
    WebSocket client connected to the room as an Event (subscribe) frame carrying the
    exact eventName/attributes and the same id the HTTP call returned."""
    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(
        name=ctx.unique_name("sim2real-ivschat-room"), tags={"sim2real": CHECK}
    )
    room_arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=room_arn))

    user_id = "sim2real-native-listener"
    token = ivschat.create_chat_token(roomIdentifier=room_arn, userId=user_id)["token"]
    ws = _ws_connect(ctx, token)
    ctx.on_cleanup(ws.close)

    sent = ivschat.send_event(
        roomIdentifier=room_arn, eventName="sim2real_custom_event", attributes={"k": "v"}
    )
    event_id = sent["id"]

    evt = _ws_recv_until(ws, lambda m: m.get("Type") == "EVENT", timeout_s=20.0)

    assert evt["EventName"] == "sim2real_custom_event", (
        f"expected EventName 'sim2real_custom_event', got {evt.get('EventName')!r}"
    )
    assert evt["Attributes"] == {"k": "v"}, f"expected Attributes {{'k': 'v'}}, got {evt.get('Attributes')!r}"
    assert evt["Id"] == event_id, (
        f"expected websocket Event id to match SendEvent response id {event_id!r}, got {evt.get('Id')!r}"
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
