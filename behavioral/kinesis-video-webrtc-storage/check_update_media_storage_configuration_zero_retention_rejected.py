"""update-media-storage-configuration-zero-retention-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-media-storage-configuration-zero-retention-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateMediaStorageConfiguration rejects enabling storage against a stream created with
    DataRetentionInHours=0 with NoDataRetentionException; the same channel links successfully
    to a fresh stream that has a positive retention period (positive control)."""
    setup = _create_channel_and_stream(ctx, link_storage=False, retention_hours=0)
    kv = setup["kv"]

    error = _client_error(
        lambda: kv.update_media_storage_configuration(
            ChannelARN=setup["channel_arn"],
            MediaStorageConfiguration={"StreamARN": setup["stream_arn"], "Status": "ENABLED"},
        )
    )
    assert error.get("Code") == "NoDataRetentionException", error
    expected_message = "The stream data retention is set to 0 hours."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    try:
        cfg = kv.describe_media_storage_configuration(ChannelARN=setup["channel_arn"])[
            "MediaStorageConfiguration"
        ]
        assert cfg.get("Status") != "ENABLED", "channel should not have been linked after the rejection"
    except ClientError:
        pass  # no media storage configuration exists yet, which also confirms nothing was linked

    retentive_stream_name = ctx.unique_name("sim2real-kvsrtc-strm2-")
    retentive_stream_arn = kv.create_stream(StreamName=retentive_stream_name, DataRetentionInHours=1)[
        "StreamARN"
    ]
    ctx.on_cleanup(lambda: _safe_delete_stream(kv, retentive_stream_arn))
    _wait_stream_active(kv, retentive_stream_arn)

    kv.update_media_storage_configuration(
        ChannelARN=setup["channel_arn"],
        MediaStorageConfiguration={"StreamARN": retentive_stream_arn, "Status": "ENABLED"},
    )
    ctx.on_cleanup(lambda: _safe_unlink(kv, setup["channel_arn"]))

    linked = kv.describe_media_storage_configuration(ChannelARN=setup["channel_arn"])[
        "MediaStorageConfiguration"
    ]
    assert linked["Status"] == "ENABLED", f"expected ENABLED after the control link, got {linked}"
    assert linked["StreamARN"] == retentive_stream_arn, (
        f"expected StreamARN {retentive_stream_arn}, got {linked}"
    )


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
