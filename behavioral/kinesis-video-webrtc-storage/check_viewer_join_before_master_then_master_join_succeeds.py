"""viewer-join-before-master-then-master-join-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "viewer-join-before-master-then-master-join-succeeds"
GROUP = "state"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a storage-enabled channel, a viewer's JoinStorageSessionAsViewer succeeds before any "MASTER" peer has
    joined, and a "MASTER" peer's JoinStorageSession on the same channel then succeeds."""
    setup = _create_channel_and_stream(ctx)
    kv = setup["kv"]
    channel_arn = setup["channel_arn"]
    viewer_webrtc = ctx.client(
        "kinesis-video-webrtc-storage", endpoint_url=_webrtc_endpoint(kv, channel_arn, "VIEWER")
    )
    primary_webrtc = ctx.client(
        "kinesis-video-webrtc-storage", endpoint_url=_webrtc_endpoint(kv, channel_arn, "MASTER")
    )

    viewer_webrtc.join_storage_session_as_viewer(channelArn=channel_arn, clientId=ctx.unique_name("viewer-"))
    primary_webrtc.join_storage_session(channelArn=channel_arn)


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


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-kvsrtc"}


def _create_channel_and_stream(ctx, link_storage=True, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    channel_name = ctx.unique_name("sim2real-kvsrtc-ch-")
    stream_name = ctx.unique_name("sim2real-kvsrtc-strm-")
    channel_tags = [{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]
    channel_arn = kv.create_signaling_channel(
        ChannelName=channel_name, ChannelType="SINGLE_MASTER", Tags=channel_tags
    )["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kv, channel_arn))
    stream_arn = kv.create_stream(
        StreamName=stream_name, DataRetentionInHours=retention_hours, Tags=_mgmt_tags()
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
