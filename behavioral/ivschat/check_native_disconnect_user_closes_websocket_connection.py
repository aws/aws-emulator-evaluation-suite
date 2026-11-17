"""native-disconnect-user-closes-websocket-connection."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "native-disconnect-user-closes-websocket-connection"
GROUP = "data-plane"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DisconnectUser (an HTTP/IAM-authorized moderation call) actually terminates the
    target user's live WebSocket connection to the room, not merely records intent."""
    import websocket

    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(
        name=ctx.unique_name("sim2real-ivschat-room"),
        tags={"sim2real-check": CHECK},
    )
    room_arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=room_arn))

    target_id = "sim2real-native-disconnectee"
    control_id = "sim2real-native-bystander"
    target_token = ivschat.create_chat_token(roomIdentifier=room_arn, userId=target_id)["token"]
    control_token = ivschat.create_chat_token(roomIdentifier=room_arn, userId=control_id)["token"]

    target_ws = _ws_connect(ctx, target_token)
    ctx.on_cleanup(target_ws.close)
    control_ws = _ws_connect(ctx, control_token)
    ctx.on_cleanup(control_ws.close)

    ivschat.disconnect_user(roomIdentifier=room_arn, userId=target_id, reason="sim2real-test")

    # Twin control: the bystander's socket must survive the exact window in which the target's is
    # expected to close, so a general outage or idle timeout cannot masquerade as DisconnectUser's
    # effect.
    target_closed = False
    control_survived = True
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline and not target_closed:
        try:
            target_ws.settimeout(2.0)
            raw = target_ws.recv()
            if raw == "":
                target_closed = True
        except websocket.WebSocketTimeoutException:
            pass
        except websocket.WebSocketConnectionClosedException:
            target_closed = True

        try:
            control_ws.settimeout(0.1)
            control_ws.recv()
        except websocket.WebSocketTimeoutException:
            pass
        except websocket.WebSocketConnectionClosedException:
            control_survived = False

    assert target_closed, "WebSocket connection remained open after DisconnectUser"
    assert control_survived, (
        "bystander's WebSocket connection also closed; the target's closure cannot be "
        "attributed to DisconnectUser specifically"
    )

    control_ws.settimeout(2.0)
    try:
        control_ws.ping()
    except Exception as exc:  # noqa: BLE001 - any failure here is a genuine liveness defect
        raise AssertionError(
            f"bystander's WebSocket connection is no longer usable after the target's "
            f"disconnect: {exc}"
        ) from exc


def _ws_connect(ctx, token):
    import websocket
    endpoint = ctx.service_url(f"wss://edge.ivschat.{ctx.region}.amazonaws.com")
    return websocket.create_connection(endpoint, subprotocols=[token], timeout=20)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
