"""delete-signaling-channel-while-linked-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-signaling-channel-while-linked-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSignalingChannel on a channel linked to a stream fails with ResourceInUseException and the exact
    message, leaving the channel ACTIVE; after unlinking, the same delete succeeds and the channel is gone
    (a later UpdateMediaStorageConfiguration on its ARN fails with ResourceNotFoundException)."""
    setup = _create_channel_and_stream(ctx)
    kv = setup["kv"]
    channel_arn = setup["channel_arn"]

    error = _client_error(lambda: kv.delete_signaling_channel(ChannelARN=channel_arn))
    assert error.get("Code") == "ResourceInUseException", error
    expected_message = "Disable MediaStorageConfiguration to delete the channel"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    still_active = kv.describe_signaling_channel(ChannelARN=channel_arn)["ChannelInfo"]["ChannelStatus"]
    assert still_active == "ACTIVE", "channel should not have been deleted while still linked"

    kv.update_media_storage_configuration(
        ChannelARN=channel_arn, MediaStorageConfiguration={"Status": "DISABLED"}
    )

    # Positive control: the identical delete succeeds once the channel is unlinked.
    kv.delete_signaling_channel(ChannelARN=channel_arn)

    # The mutating call's own (non-)exception is not the verdict: an independent read must show
    # the channel actually gone. DeleteSignalingChannel is asynchronous, so this is a bounded
    # poll, not a single read.
    _wait_channel_gone(kv, channel_arn)

    dead = _client_error(
        lambda: kv.update_media_storage_configuration(
            ChannelARN=channel_arn, MediaStorageConfiguration={"Status": "DISABLED"}
        )
    )
    assert dead.get("Code") == "ResourceNotFoundException", (
        f"a mutation on the deleted channel's ARN should fail not-found, got {dead}"
    )
    expected_dead_message = "The requested channel is not found or not active."
    assert dead.get("Message") == expected_dead_message, (
        f"expected message {expected_dead_message!r}, got {dead.get('Message')!r}"
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


def _wait_channel_gone(kv, channel_arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            kv.describe_signaling_channel(ChannelARN=channel_arn)
            last_code = None
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code == "ResourceNotFoundException":
                return
        time.sleep(interval_s)
    raise AssertionError(
        f"channel {channel_arn!r} was not removed within {timeout_s}s (last code {last_code!r})"
    )


def _create_channel_and_stream(ctx, link_storage=True, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    channel_name = ctx.unique_name("sim2real-kvsrtc-ch-")
    stream_name = ctx.unique_name("sim2real-kvsrtc-strm-")
    channel_arn = kv.create_signaling_channel(
        ChannelName=channel_name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kv, channel_arn))
    stream_arn = kv.create_stream(
        StreamName=stream_name,
        DataRetentionInHours=retention_hours,
        Tags={"sim2real": CHECK},
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
