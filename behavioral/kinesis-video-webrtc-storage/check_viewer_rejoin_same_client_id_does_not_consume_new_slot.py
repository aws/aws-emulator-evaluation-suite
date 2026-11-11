"""viewer-rejoin-same-client-id-does-not-consume-new-slot."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "viewer-rejoin-same-client-id-does-not-consume-new-slot"
GROUP = "state"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With 3 distinct viewers joined, JoinStorageSessionAsViewer with one of their client ids succeeds again,
    while a 4th distinct client id fails with ClientLimitExceededException and the exact message: the viewer
    cap counts distinct client ids, not calls."""
    setup = _create_channel_and_stream(ctx)
    kv = setup["kv"]
    channel_arn = setup["channel_arn"]
    webrtc = ctx.client(
        "kinesis-video-webrtc-storage", endpoint_url=_webrtc_endpoint(kv, channel_arn, "VIEWER")
    )

    client_a = ctx.unique_name("viewer-a-")
    client_b = ctx.unique_name("viewer-b-")
    client_c = ctx.unique_name("viewer-c-")

    for client_id in (client_a, client_b, client_c):
        webrtc.join_storage_session_as_viewer(channelArn=channel_arn, clientId=client_id)

    # Confirm the quota is full right away (no intervening calls or delay) with a new 4th
    # distinct clientId, so no viewer registration can have expired in between.
    client_d = ctx.unique_name("viewer-d-")
    fourth = _client_error(
        lambda: webrtc.join_storage_session_as_viewer(channelArn=channel_arn, clientId=client_d)
    )
    assert fourth.get("Code") == "ClientLimitExceededException", (
        f"expected a genuinely new 4th distinct viewer to be capped while quota is full, got {fourth}"
    )
    expected_message = "Maximum number of viewers connected to the session!"
    assert fourth.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {fourth.get('Message')!r}"
    )

    # With the quota still full, rejoining with an ALREADY-COUNTED clientId (client_a) must
    # still succeed -- it reuses its existing slot rather than requiring a free one.
    webrtc.join_storage_session_as_viewer(channelArn=channel_arn, clientId=client_a)


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
    channel_arn = kv.create_signaling_channel(
        ChannelName=channel_name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kv, channel_arn))
    stream_arn = kv.create_stream(
        StreamName=stream_name,
        DataRetentionInHours=retention_hours,
        Tags={"sim2real-check": CHECK},
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


def _client_error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises, so a
    target that accepts what AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
