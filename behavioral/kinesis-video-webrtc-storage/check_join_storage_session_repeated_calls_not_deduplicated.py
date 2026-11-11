"""join-storage-session-repeated-calls-not-deduplicated."""
from __future__ import annotations

import json
import threading
import time
import urllib.parse

from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "join-storage-session-repeated-calls-not-deduplicated"
GROUP = "state"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:happy-path", "cap:c1", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """JoinStorageSession is not idempotent: two calls in a row on the same channel both succeed, and the
    "MASTER" peer's WSS connection receives an SDP_OFFER with a non-empty payload for each, the two
    payloads different."""
    from websockets.sync.client import connect as ws_connect

    setup = _create_channel_and_stream(ctx)
    kv = setup["kv"]
    channel_arn = setup["channel_arn"]

    wss_endpoint = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": ["WSS"], "Role": "MASTER"},
    )["ResourceEndpointList"][0]["ResourceEndpoint"]
    url = _sign_wss_url(kv, ctx.region, wss_endpoint, channel_arn)

    webrtc_endpoint = _webrtc_endpoint(kv, channel_arn, "MASTER")
    webrtc = ctx.client("kinesis-video-webrtc-storage", endpoint_url=ctx.endpoint_url(webrtc_endpoint))

    target_url, route_headers = ctx.endpoint_route(url, websocket=True)
    tls = _ssl_context(ctx.http_verify) if target_url.startswith("wss://") else None
    with ws_connect(target_url, additional_headers=route_headers, ssl=tls, open_timeout=20) as ws:
        first_err, first_msg = _join_and_recv_offer(ws, webrtc, channel_arn)
        assert first_err is None, f"expected the first JoinStorageSession call to succeed, got {first_err}"
        assert first_msg.get("messageType") == "SDP_OFFER", (
            f"expected an SDP_OFFER pushed for the first join, got {first_msg}"
        )
        assert first_msg.get("messagePayload"), f"first SDP_OFFER carried no messagePayload: {first_msg}"

        second_err, second_msg = _join_and_recv_offer(ws, webrtc, channel_arn)
        assert second_err is None, (
            f"expected the repeated JoinStorageSession call to succeed (not deduplicated/rejected), "
            f"got {second_err}"
        )
        assert second_msg.get("messageType") == "SDP_OFFER", (
            f"expected a SECOND independent SDP_OFFER pushed for the repeated join, got {second_msg}"
        )
        assert second_msg.get("messagePayload"), f"second SDP_OFFER carried no messagePayload: {second_msg}"

    assert second_msg["messagePayload"] != first_msg["messagePayload"], (
        "expected the repeated JoinStorageSession call to push its OWN SDP offer, not a deduplicated "
        f"copy of the first (both payloads were identical): {first_msg}"
    )


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _join_and_recv_offer(ws, webrtc, channel_arn):
    join_result: dict = {}

    def _join():
        try:
            webrtc.join_storage_session(channelArn=channel_arn)
        except ClientError as e:
            join_result["error"] = e.response["Error"]["Code"]

    joiner = threading.Thread(target=_join, daemon=True)
    joiner.start()
    # The channel interleaves ICE_CANDIDATE messages with the SDP_OFFER, so drain until this
    # join's offer arrives or the window lapses; the last message read is returned otherwise.
    message: dict = {}
    deadline = time.monotonic() + 30
    while message.get("messageType") != "SDP_OFFER" and time.monotonic() < deadline:
        try:
            raw = ws.recv(timeout=max(0.1, deadline - time.monotonic()))
        except TimeoutError:
            break
        message = json.loads(raw)
    joiner.join(timeout=5)
    return join_result.get("error"), message


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


def _webrtc_endpoint(kv, channel_arn, role):
    resp = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": ["WEBRTC"], "Role": role},
    )
    for e in resp["ResourceEndpointList"]:
        if e["Protocol"] == "WEBRTC":
            return e["ResourceEndpoint"]
    raise AssertionError(f"no WEBRTC endpoint returned for role={role}")


def _create_channel_and_stream(ctx, link_storage=True, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    channel_name = ctx.unique_name("sim2real-kvsrtc-ch-")
    stream_name = ctx.unique_name("sim2real-kvsrtc-strm-")
    channel_arn = kv.create_signaling_channel(ChannelName=channel_name, ChannelType="SINGLE_MASTER")[
        "ChannelARN"
    ]
    ctx.on_cleanup(lambda: _safe_delete_channel(kv, channel_arn))
    stream_arn = kv.create_stream(StreamName=stream_name, DataRetentionInHours=retention_hours)["StreamARN"]
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
