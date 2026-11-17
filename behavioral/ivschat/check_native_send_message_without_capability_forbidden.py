"""native-send-message-without-capability-forbidden."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "native-send-message-without-capability-forbidden"
GROUP = "overly-permissive"
SERVICES = ["ivschat"]


@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A connection whose token lacks SEND_MESSAGE gets an ERROR frame (403, "missing SEND_MESSAGE
    capability") and an observer never sees its message, while a connection with the capability sends and
    is delivered."""
    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(
        name=ctx.unique_name("sim2real-ivschat-room"), tags={"sim2real": "true"}
    )
    room_arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=room_arn))

    empowered_token = ivschat.create_chat_token(
        roomIdentifier=room_arn, userId="sim2real-empowered", capabilities=["SEND_MESSAGE"]
    )["token"]
    empowered_ws = _ws_connect(ctx, empowered_token)
    ctx.on_cleanup(empowered_ws.close)

    # A third connection with no send capability at all -- it never publishes, it only
    # watches. It is the independent read at the destination that the sender's own
    # transcript cannot provide: whatever it does or does not see is what the room actually
    # broadcast, not what either sender's own connection was told.
    observer_token = ivschat.create_chat_token(roomIdentifier=room_arn, userId="sim2real-observer")["token"]
    observer_ws = _ws_connect(ctx, observer_token)
    ctx.on_cleanup(observer_ws.close)

    # Positive control first, so a target with no delivery path at all cannot score green on
    # the absence check below: send once while healthy, and measure how long the broker takes
    # to relay it to the observer. That measured latency -- not a guess -- calibrates the
    # absence window.
    control_start = time.monotonic()
    empowered_ws.send(
        json.dumps({"Action": "SEND_MESSAGE", "Content": "control-ping", "RequestId": "req-control"})
    )
    control_ack = _ws_recv_until(empowered_ws, lambda m: m.get("RequestId") == "req-control", timeout_s=20.0)
    assert control_ack["Type"] == "MESSAGE", f"expected MESSAGE ack for control send, got {control_ack!r}"
    control_seen = _ws_recv_until(
        observer_ws, lambda m: m.get("Type") == "MESSAGE" and m.get("Content") == "control-ping", timeout_s=20.0
    )
    assert control_seen["Content"] == "control-ping", (
        f"observer never saw the control-ping broadcast: {control_seen!r}"
    )
    relay_latency_s = max(time.monotonic() - control_start, 0.5)

    # Break exactly one thing: a connection with no capabilities at all -- only the implicit
    # view capability -- tries to publish.
    powerless_token = ivschat.create_chat_token(
        roomIdentifier=room_arn, userId="sim2real-powerless"
    )["token"]
    powerless_ws = _ws_connect(ctx, powerless_token)
    ctx.on_cleanup(powerless_ws.close)

    powerless_ws.send(
        json.dumps({"Action": "SEND_MESSAGE", "Content": "should-be-blocked", "RequestId": "req-bad"})
    )
    err = _ws_recv_until(powerless_ws, lambda m: m.get("Type") == "ERROR", timeout_s=20.0)
    assert err.get("ErrorCode") == 403, f"expected ERROR 403 for capability-less SEND_MESSAGE, got {err!r}"
    assert err.get("ErrorMessage") == "missing SEND_MESSAGE capability", f"ERROR frame: {err!r}"

    # Effect absent, via the independent observer: hold for >=3x the measured relay latency,
    # long enough for a genuine broadcast to have arrived, and demand it never does.
    leaked = _ws_recv_within(
        observer_ws, lambda m: m.get("Content") == "should-be-blocked", timeout_s=3 * relay_latency_s
    )
    assert leaked is None, f"blocked message was broadcast to an independent observer: {leaked!r}"

    # No restore beat: a chat token's capabilities are fixed at issuance, so the powerless
    # connection can never become empowered in place. The restore is a DIFFERENT connection
    # holding the capability, asserted end-to-end at the same independent observer.
    empowered_ws.send(
        json.dumps({"Action": "SEND_MESSAGE", "Content": "allowed", "RequestId": "req-good"})
    )
    ok = _ws_recv_until(empowered_ws, lambda m: m.get("RequestId") == "req-good", timeout_s=20.0)
    assert ok["Type"] == "MESSAGE", f"expected MESSAGE ack for the empowered send, got {ok!r}"
    assert ok["Content"] == "allowed", f"expected echoed content 'allowed', got {ok.get('Content')!r}"
    seen = _ws_recv_until(
        observer_ws, lambda m: m.get("Type") == "MESSAGE" and m.get("Content") == "allowed", timeout_s=20.0
    )
    assert seen["Content"] == "allowed", f"observer never saw the allowed broadcast: {seen!r}"


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


def _ws_recv_within(ws, predicate, timeout_s):
    """Like `_ws_recv_until`, but absence is success: returns the matching message if one
    arrives before the deadline, or None if the deadline passes with no match -- never raises
    on timeout, since the caller is proving something did NOT happen."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(0.1, deadline - time.monotonic())
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
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
