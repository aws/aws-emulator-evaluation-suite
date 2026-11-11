"""kvs-signaling-wss-offer-answer-roundtrip."""
from __future__ import annotations

import asyncio
import base64
import json
import time
from urllib.parse import urlencode

from behavioral_harness import tags

CHECK = "kvs-signaling-wss-offer-answer-roundtrip"
GROUP = "native-protocol"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:happy-path", "cap:c1", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A VIEWER's SDP_OFFER sent over the channel's SigV4-signed WSS endpoint reaches the "MASTER" peer with
    the same payload and sender client id, and the "MASTER" peer's SDP_ANSWER reaches the VIEWER with the
    same payload."""
    import websockets  # noqa: F401

    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-native-")
    arn = kv.create_signaling_channel(
        ChannelName=name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ChannelARN"]
    ctx.on_cleanup(lambda: kv.delete_signaling_channel(ChannelARN=arn))
    _wait_channel_status(ctx, name, "ACTIVE")

    primary_wss = _get_endpoint(ctx, arn, "WSS", "MASTER")
    viewer_wss = _get_endpoint(ctx, arn, "WSS", "VIEWER")
    client_id = ctx.unique_name("viewer-")
    primary_route = ctx.endpoint_route(_presigned_wss_url(ctx, primary_wss, arn), websocket=True)
    viewer_route = ctx.endpoint_route(
        _presigned_wss_url(ctx, viewer_wss, arn, client_id=client_id), websocket=True
    )

    offer_b64 = base64.b64encode(b"native-protocol-sdp-offer-payload").decode()
    answer_b64 = base64.b64encode(b"native-protocol-sdp-answer-payload").decode()

    offer_event, answer_event = asyncio.run(
        _wss_offer_answer_session(primary_route, viewer_route, offer_b64, answer_b64)
    )

    assert offer_event["messageType"] == "SDP_OFFER", (
        f"expected the 'MASTER' peer to receive messageType SDP_OFFER, got {offer_event['messageType']!r}"
    )
    assert offer_event["messagePayload"] == offer_b64, (
        f"expected the 'MASTER' peer to receive payload {offer_b64!r}, got {offer_event['messagePayload']!r}"
    )
    assert offer_event["senderClientId"] == client_id, (
        f"expected the 'MASTER' peer to see senderClientId {client_id!r}, got {offer_event['senderClientId']!r}"
    )

    assert answer_event["messageType"] == "SDP_ANSWER", (
        f"expected the viewer to receive messageType SDP_ANSWER, got {answer_event['messageType']!r}"
    )
    assert answer_event["messagePayload"] == answer_b64, (
        f"expected the viewer to receive payload {answer_b64!r}, got {answer_event['messagePayload']!r}"
    )


async def _wss_offer_answer_session(primary_route, viewer_route, offer_b64, answer_b64, timeout_s=25.0):
    import websockets

    async with websockets.connect(
        primary_route[0], additional_headers=primary_route[1], open_timeout=timeout_s
    ) as primary_ws:
        async with websockets.connect(
            viewer_route[0], additional_headers=viewer_route[1], open_timeout=timeout_s
        ) as viewer_ws:
            await viewer_ws.send(
                json.dumps(
                    {
                        "action": "SDP_OFFER",
                        "recipientClientId": "master",
                        "messagePayload": offer_b64,
                    }
                )
            )
            offer_event = await _recv_message(primary_ws, "SDP_OFFER", timeout_s)

            await primary_ws.send(
                json.dumps(
                    {
                        "action": "SDP_ANSWER",
                        "recipientClientId": offer_event["senderClientId"],
                        "messagePayload": answer_b64,
                    }
                )
            )
            answer_event = await _recv_message(viewer_ws, "SDP_ANSWER", timeout_s)

    return offer_event, answer_event


async def _recv_message(ws, expected_message_type, timeout_s):
    """The WSS channel may interleave an empty keep-alive frame ahead of the SDP
    message; skip frames that are empty or carry a different messageType, bounded
    by the same deadline as a normal recv."""
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for a {expected_message_type!r} message"
            )
        raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        if not raw:
            continue
        event = json.loads(raw)
        if event.get("messageType") == expected_message_type:
            return event


def _wait_channel_status(ctx, name, target_status, timeout_s=60.0, interval_s=1.5):
    kv = ctx.client("kinesisvideo")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kv.describe_signaling_channel(ChannelName=name)["ChannelInfo"]
        last = info.get("ChannelStatus")
        if last == target_status:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"channel {name!r} did not reach status {target_status!r}; last seen {last!r}")


def _get_endpoint(ctx, channel_arn, protocol, role):
    kv = ctx.client("kinesisvideo")
    resp = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": [protocol], "Role": role},
    )
    for entry in resp["ResourceEndpointList"]:
        if entry["Protocol"] == protocol:
            return entry["ResourceEndpoint"]
    raise AssertionError(f"no {protocol} endpoint returned for channel {channel_arn}")


def _presigned_wss_url(ctx, wss_endpoint, channel_arn, client_id=None):
    from botocore.auth import SigV4QueryAuth
    from botocore.awsrequest import AWSRequest

    creds = ctx.client("kinesisvideo")._request_signer._credentials.get_frozen_credentials()
    params = {"X-Amz-ChannelARN": channel_arn}
    if client_id:
        params["X-Amz-ClientId"] = client_id
    request = AWSRequest(method="GET", url=f"{wss_endpoint}?{urlencode(params)}")
    SigV4QueryAuth(creds, "kinesisvideo", ctx.region, expires=299).add_auth(request)
    return request.url


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
