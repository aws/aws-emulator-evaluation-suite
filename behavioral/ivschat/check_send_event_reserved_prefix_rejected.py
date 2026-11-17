"""send-event-reserved-prefix-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "send-event-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivschat"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected SendEvent to be rejected, it succeeded with {result!r}")


@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEvent with an eventName under the reserved "aws:" prefix fails with ValidationException and its
    exact message; a subscriber's first EVENT frame is the application event sent next, with the id that
    SendEvent returned."""
    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(name=ctx.unique_name("sim2real-ivschat-room"))
    room_arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=room_arn))

    token = ivschat.create_chat_token(roomIdentifier=room_arn, userId="sim2real-listener")["token"]
    ws = _ws_connect(ctx, token)
    ctx.on_cleanup(ws.close)

    code, message = _error(
        lambda: ivschat.send_event(roomIdentifier=room_arn, eventName="aws:not_allowed")
    )
    assert code == "ValidationException", code
    assert message == (
        'Request member: eventName failed to satisfy the constraints: prefix "aws:" on eventName '
        'is reserved by the service, eventName="aws:not_allowed"'
    ), message

    control = ivschat.send_event(roomIdentifier=room_arn, eventName="app_defined_event")
    assert "id" in control and len(control["id"]) == 12

    evt = _ws_recv_until(ws, lambda m: m.get("Type") == "EVENT", timeout_s=20.0)
    assert evt["EventName"] == "app_defined_event", evt
    assert evt["Id"] == control["id"], evt


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
