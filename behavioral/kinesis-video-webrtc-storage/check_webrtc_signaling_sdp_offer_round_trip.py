"""webrtc-signaling-sdp-offer-round-trip."""
from __future__ import annotations

import base64
import json
import threading
import time
import urllib.parse

from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webrtc-signaling-sdp-offer-round-trip"
GROUP = "native-protocol"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After the "MASTER" peer connects to the channel's WSS endpoint, JoinStorageSession succeeds and the connection
    receives an SDP_OFFER whose decoded payload is an "offer" envelope with an SDP starting "v=0" and carrying
    an "m=" media line."""
    from websockets.sync.client import connect as ws_connect

    setup = _create_channel_and_stream(ctx)
    kv = setup["kv"]
    channel_arn = setup["channel_arn"]

    endpoint = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": ["WSS"], "Role": "MASTER"},
    )["ResourceEndpointList"][0]["ResourceEndpoint"]

    url = _sign_wss_url(kv, ctx.region, endpoint, channel_arn)

    primary_endpoint = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": ["WEBRTC"], "Role": "MASTER"},
    )["ResourceEndpointList"][0]["ResourceEndpoint"]
    webrtc = ctx.client("kinesis-video-webrtc-storage", endpoint_url=ctx.endpoint_url(primary_endpoint))
    join_result: dict = {}

    target_url, route_headers = ctx.endpoint_route(url, websocket=True)
    tls = _ssl_context(ctx.http_verify) if target_url.startswith("wss://") else None
    with ws_connect(target_url, additional_headers=route_headers, ssl=tls, open_timeout=20) as ws:

        def _join():
            try:
                webrtc.join_storage_session(channelArn=channel_arn)
            except ClientError as e:
                join_result["error"] = e

        joiner = threading.Thread(target=_join, daemon=True)
        joiner.start()

        # The storage session's WSS channel interleaves ICE_CANDIDATE traffic with the
        # SDP_OFFER, so the first message received is not reliably the offer -- drain
        # until the offer arrives or the bounded window (deadline, not a sleep) lapses.
        message = None
        deadline = time.monotonic() + 30
        while message is None and time.monotonic() < deadline:
            try:
                raw = ws.recv(timeout=max(0.1, deadline - time.monotonic()))
            except TimeoutError:
                break
            candidate = json.loads(raw)
            if candidate.get("messageType") == "SDP_OFFER":
                message = candidate
        joiner.join(timeout=5)

    assert "error" not in join_result, f"JoinStorageSession failed: {join_result['error']}"
    assert message is not None, (
        "storage session never pushed an SDP_OFFER within 30s of JoinStorageSession"
    )
    payload_b64 = message.get("messagePayload")
    assert payload_b64, f"SDP_OFFER message carried no messagePayload: {message}"
    envelope = json.loads(base64.b64decode(payload_b64))
    assert envelope.get("type") == "offer", (
        f"messagePayload decoded to a description envelope of the wrong type, got: {envelope}"
    )
    sdp = envelope.get("sdp", "")
    assert sdp.startswith("v=0"), (
        f"envelope's 'sdp' field is not a real SDP offer (RFC 4566 'v=0' session line), got: {sdp[:200]!r}"
    )
    assert "m=" in sdp, f"decoded SDP offer carried no media ('m=') line, got: {sdp[:500]!r}"


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _sign_wss_url(kv_client, region, endpoint, channel_arn):
    https_endpoint = endpoint.replace("wss://", "https://", 1)
    query = urllib.parse.urlencode({"X-Amz-ChannelARN": channel_arn})
    req = AWSRequest(method="GET", url=f"{https_endpoint}?{query}")
    creds = kv_client._request_signer._credentials.get_frozen_credentials()
    SigV4QueryAuth(creds, "kinesisvideo", region, expires=299).add_auth(req)
    return req.url.replace("https://", "wss://", 1)


def _wait_channel_active(kv, channel_arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_signaling_channel(ChannelARN=channel_arn)["ChannelInfo"]["ChannelStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"signaling channel never reached ACTIVE (last status={status})")


def _wait_stream_active(kv, stream_arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_stream(StreamARN=stream_arn)["StreamInfo"]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream never reached ACTIVE (last status={status})")


def _safe_delete_channel(kv, channel_arn):
    try:
        kv.delete_signaling_channel(ChannelARN=channel_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_stream(kv, stream_arn):
    try:
        kv.delete_stream(StreamARN=stream_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_unlink(kv, channel_arn):
    try:
        kv.update_media_storage_configuration(
            ChannelARN=channel_arn, MediaStorageConfiguration={"Status": "DISABLED"}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_channel_and_stream(ctx, link_storage=True, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    channel_name = ctx.unique_name("sim2real-kvsrtc-ch-")
    stream_name = ctx.unique_name("sim2real-kvsrtc-strm-")
    channel_tags = [{"Key": "sim2real", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}]
    stream_tags = {"sim2real": "true", "sim2real-check": CHECK}
    channel_arn = kv.create_signaling_channel(
        ChannelName=channel_name, ChannelType="SINGLE_MASTER", Tags=channel_tags
    )["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kv, channel_arn))
    stream_arn = kv.create_stream(
        StreamName=stream_name, DataRetentionInHours=retention_hours, Tags=stream_tags
    )["StreamARN"]
    ctx.on_cleanup(lambda: _safe_delete_stream(kv, stream_arn))
    _wait_channel_active(kv, channel_arn)
    _wait_stream_active(kv, stream_arn)
    if link_storage:
        kv.update_media_storage_configuration(
            ChannelARN=channel_arn,
            MediaStorageConfiguration={"StreamARN": stream_arn, "Status": "ENABLED"},
        )
        ctx.on_cleanup(lambda: _safe_unlink(kv, channel_arn))
    return {
        "kv": kv,
        "channel_arn": channel_arn,
        "stream_arn": stream_arn,
        "channel_name": channel_name,
        "stream_name": stream_name,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
