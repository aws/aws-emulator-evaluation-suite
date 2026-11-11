"""viewer-slot-limit-independent-per-channel."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "viewer-slot-limit-independent-per-channel"
GROUP = "state"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """The 3-viewer quota is tracked per signaling channel, not per account: filling one
    channel's 3 viewer slots (and being capped on a 4th) has no effect on a second,
    independent channel's own viewer joining successfully."""
    channel_a = _create_channel_and_stream(ctx)
    channel_b = _create_channel_and_stream(ctx)
    kv = channel_a["kv"]
    webrtc_a = ctx.client(
        "kinesis-video-webrtc-storage", endpoint_url=_webrtc_endpoint(kv, channel_a["channel_arn"], "VIEWER")
    )
    webrtc_b = ctx.client(
        "kinesis-video-webrtc-storage", endpoint_url=_webrtc_endpoint(kv, channel_b["channel_arn"], "VIEWER")
    )

    for i in range(3):
        client_id = ctx.unique_name(f"viewer-a{i}-")
        webrtc_a.join_storage_session_as_viewer(channelArn=channel_a["channel_arn"], clientId=client_id)

    extra_id = ctx.unique_name("viewer-a-extra-")
    fourth = _client_error(
        lambda: webrtc_a.join_storage_session_as_viewer(channelArn=channel_a["channel_arn"], clientId=extra_id)
    )
    assert fourth.get("Code") == "ClientLimitExceededException", (
        f"expected channel A's 4th viewer to be capped, got {fourth}"
    )
    expected_message = "Maximum number of viewers connected to the session!"
    assert fourth.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {fourth.get('Message')!r}"
    )

    other_id = ctx.unique_name("viewer-b-")
    webrtc_b.join_storage_session_as_viewer(channelArn=channel_b["channel_arn"], clientId=other_id)


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
