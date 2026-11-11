"""send-alexa-offer-to-master-master-connectivity-gates-delivery."""
from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

from behavioral_harness import tags

CHECK = "send-alexa-offer-to-master-master-connectivity-gates-delivery"
GROUP = "state"
SERVICES = ["kinesis-video-signaling"]


@tags(
    "axis:negative-delivery", "cap:c1", "cap:c6", "concern:data-plane", "concern:negative-classes",
    "dp:api", "plane:data",
)
def run(ctx) -> None:
    """The "SendAlexaOfferToMaster" call returns the SDP answer the connected primary peer sends back over WSS; with
    that peer disconnected the identical call is still accepted (HTTP 200) but carries no Answer, and
    reconnecting a peer restores a real Answer."""
    import websockets  # noqa: F401

    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-alexa-")
    # short MessageTtlSeconds (minimum allowed) bounds any redelivery-window wait on the
    # "no peer connected" call below to a few seconds instead of an undocumented default
    arn = kv.create_signaling_channel(
        ChannelName=name,
        ChannelType="SINGLE_MASTER",
        SingleMasterConfiguration={"MessageTtlSeconds": 5},
    )["ChannelARN"]
    ctx.on_cleanup(lambda: kv.delete_signaling_channel(ChannelARN=arn))
    _wait_channel_status(ctx, name, "ACTIVE")

    master_wss = _get_endpoint(ctx, arn, "WSS", "MASTER")
    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "MASTER")
    master_route = ctx.endpoint_route(_presigned_wss_url(ctx, master_wss, arn), websocket=True)
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    sender_client_id = ctx.unique_name("alexa-")
    offer_b64 = base64.b64encode(b"alexa-sdp-offer-payload").decode()
    answer_b64 = base64.b64encode(b"alexa-sdp-answer-payload").decode()

    # Phase 1: primary peer connected -> the REST call is delivered and returns the real answer
    connected = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        rest_future = pool.submit(
            _offer_once_connected,
            sig,
            connected,
            ChannelARN=arn,
            SenderClientId=sender_client_id,
            MessagePayload=offer_b64,
        )
        offer_event = asyncio.run(
            _master_receive_and_answer(master_route, answer_b64, timeout_s=20.0, connected=connected)
        )
        rest_result = rest_future.result(timeout=60.0)

    assert offer_event["messageType"] == "SDP_OFFER", f"expected SDP_OFFER, got {offer_event!r}"
    assert offer_event["senderClientId"] == sender_client_id, (
        f"expected senderClientId {sender_client_id!r}, got {offer_event['senderClientId']!r}"
    )
    assert offer_event["messagePayload"] == offer_b64, (
        f"expected messagePayload {offer_b64!r}, got {offer_event['messagePayload']!r}"
    )
    assert rest_result["Answer"] == answer_b64, (
        f"expected Answer {answer_b64!r}, got {rest_result['Answer']!r}"
    )

    # Phase 2: the primary peer is disconnected (the "async with" above closed the WSS session) ->
    # the identical call against the identical channel is still ACCEPTED (real AWS blocks
    # for up to MessageTtlSeconds waiting for a live peer, then returns empty-handed) but
    # delivers no Answer -- the negative is inside the 200, not an error code
    undelivered_result = sig.send_alexa_offer_to_master(
        ChannelARN=arn, SenderClientId=sender_client_id, MessagePayload=offer_b64
    )
    assert "Answer" not in undelivered_result, (
        f"expected no Answer while no master is connected (the call blocks for "
        f"MessageTtlSeconds then returns empty-handed), got Answer={undelivered_result.get('Answer')!r}"
    )

    # Phase 3: restore -- reconnect a primary peer to the identical channel; the identical call
    # must now succeed again, proving the earlier failure was connectivity-gated and not a
    # channel-level or account-level fault
    restored_answer_b64 = base64.b64encode(b"alexa-sdp-answer-payload-restored").decode()
    connected = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as pool:
        restored_future = pool.submit(
            _offer_once_connected,
            sig,
            connected,
            ChannelARN=arn,
            SenderClientId=sender_client_id,
            MessagePayload=offer_b64,
        )
        restored_offer_event = asyncio.run(
            _master_receive_and_answer(master_route, restored_answer_b64, timeout_s=20.0, connected=connected)
        )
        restored_result = restored_future.result(timeout=60.0)

    assert restored_offer_event["messageType"] == "SDP_OFFER", (
        f"expected SDP_OFFER after restoring the master connection, got {restored_offer_event!r}"
    )
    assert restored_offer_event["senderClientId"] == sender_client_id, (
        f"expected senderClientId {sender_client_id!r} after restore, "
        f"got {restored_offer_event['senderClientId']!r}"
    )
    assert restored_result["Answer"] == restored_answer_b64, (
        f"expected the identical call to succeed again after restoring the master "
        f"connection with Answer {restored_answer_b64!r}, got {restored_result['Answer']!r}"
    )


#: Bound for the offer to reach a just-connected peer: the service may not route to it on the first call.
_OFFER_DEADLINE_S = 30.0


def _offer_once_connected(sig, connected, **kwargs):
    """SendAlexaOfferToMaster once the peer's WSS session is open, resent every 1 s while it returns no Answer."""
    if not connected.wait(timeout=30.0):
        raise AssertionError("the primary peer's WSS session never opened")
    deadline = time.monotonic() + _OFFER_DEADLINE_S
    while True:
        result = sig.send_alexa_offer_to_master(**kwargs)
        if "Answer" in result or time.monotonic() >= deadline:
            return result
        time.sleep(1.0)


async def _master_receive_and_answer(master_route, answer_b64, timeout_s=20.0, connected=None):
    import websockets

    async with websockets.connect(
        master_route[0], additional_headers=master_route[1], open_timeout=timeout_s
    ) as ws:
        if connected is not None:
            connected.set()  # the offer is sent only to a peer that is already connected
        raw = await asyncio.wait_for(ws.recv(), timeout=timeout_s + _OFFER_DEADLINE_S)
        event = json.loads(raw)
        await ws.send(
            json.dumps(
                {
                    "action": "SDP_ANSWER",
                    "recipientClientId": event["senderClientId"],
                    "messagePayload": answer_b64,
                }
            )
        )
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
