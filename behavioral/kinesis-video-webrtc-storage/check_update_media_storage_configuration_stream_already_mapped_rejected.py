"""update-media-storage-configuration-stream-already-mapped-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-media-storage-configuration-stream-already-mapped-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Linking channel B to a stream already linked to channel A fails with ResourceInUseException and the exact
    message, leaving B DISABLED; B links to its own stream, and after A releases its stream the same call
    links B to it."""
    channel_a = _create_channel_and_stream(ctx)  # linked to its own stream, ENABLED
    channel_b = _create_channel_and_stream(ctx, link_storage=False)
    kv = channel_a["kv"]

    error = _client_error(
        lambda: kv.update_media_storage_configuration(
            ChannelARN=channel_b["channel_arn"],
            MediaStorageConfiguration={"StreamARN": channel_a["stream_arn"], "Status": "ENABLED"},
        )
    )
    assert error.get("Code") == "ResourceInUseException", error
    expected_message = (
        "The channel/stream is currently not available for this operation because it is being updated."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    still_disabled = kv.describe_media_storage_configuration(ChannelARN=channel_b["channel_arn"])[
        "MediaStorageConfiguration"
    ]
    assert still_disabled["Status"] == "DISABLED", "channel B should still be unlinked after the rejection"

    kv.update_media_storage_configuration(
        ChannelARN=channel_b["channel_arn"],
        MediaStorageConfiguration={"StreamARN": channel_b["stream_arn"], "Status": "ENABLED"},
    )

    # Restore: release channel A's hold on its stream and reset channel B to a clean baseline,
    # then retry the IDENTICAL call rejected above. This distinguishes "rejected because the
    # stream is currently mapped elsewhere" from a permanent taint on the stream itself.
    kv.update_media_storage_configuration(
        ChannelARN=channel_a["channel_arn"], MediaStorageConfiguration={"Status": "DISABLED"}
    )
    kv.update_media_storage_configuration(
        ChannelARN=channel_b["channel_arn"], MediaStorageConfiguration={"Status": "DISABLED"}
    )

    kv.update_media_storage_configuration(
        ChannelARN=channel_b["channel_arn"],
        MediaStorageConfiguration={"StreamARN": channel_a["stream_arn"], "Status": "ENABLED"},
    )
    ctx.on_cleanup(lambda: _safe_unlink(kv, channel_b["channel_arn"]))

    restored = kv.describe_media_storage_configuration(ChannelARN=channel_b["channel_arn"])[
        "MediaStorageConfiguration"
    ]
    assert (
        restored["Status"] == "ENABLED" and restored["StreamARN"] == channel_a["stream_arn"]
    ), f"expected channel B linked to channel A's freed stream, got {restored}"


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
