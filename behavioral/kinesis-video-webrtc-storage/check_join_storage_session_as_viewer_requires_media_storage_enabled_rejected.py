"""join-storage-session-as-viewer-requires-media-storage-enabled-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "join-storage-session-as-viewer-requires-media-storage-enabled-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSignalingChannelEndpoint with Protocol WEBRTC on a channel without media storage fails with
    InvalidArgumentException and the exact message; after media storage is enabled on the same channel, the
    endpoint request and JoinStorageSessionAsViewer succeed."""
    setup = _create_channel_and_stream(ctx, link_storage=False)
    kv = setup["kv"]
    channel_arn = setup["channel_arn"]
    client_id = ctx.unique_name("viewer-")

    error = _expect_rejected(lambda: _webrtc_endpoint(kv, channel_arn, "VIEWER"))
    assert error.get("Code") == "InvalidArgumentException", error
    expected_message = "MediaStorageConfiguration is required for WEBRTC protocol"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    setup["kv"].update_media_storage_configuration(
        ChannelARN=channel_arn,
        MediaStorageConfiguration={"StreamARN": setup["stream_arn"], "Status": "ENABLED"},
    )
    ctx.on_cleanup(lambda: _safe_unlink(setup["kv"], channel_arn))

    endpoint = _webrtc_endpoint(kv, channel_arn, "VIEWER")
    webrtc = ctx.client("kinesis-video-webrtc-storage", endpoint_url=endpoint)
    try:
        webrtc.join_storage_session_as_viewer(channelArn=channel_arn, clientId=client_id)
    except ClientError as exc:
        raise AssertionError(
            f"expected viewer join to succeed after enabling storage, got "
            f"{exc.response['Error']['Code']}"
        ) from exc


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
    channel_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]
    stream_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
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


def _expect_rejected(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected by real AWS, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
