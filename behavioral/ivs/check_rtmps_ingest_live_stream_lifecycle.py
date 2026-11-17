"""rtmps-ingest-live-stream-lifecycle."""
from __future__ import annotations

import shutil
import subprocess
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "rtmps-ingest-live-stream-lifecycle"
GROUP = "native-protocol"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stream pushed over RTMPS goes LIVE in GetStream, InsertAdBreak without an ad configuration fails
    ValidationException, StopStream returns the channel to ChannelNotBroadcasting, and after DeleteChannel
    GetChannel fails ResourceNotFoundException, each with the exact message."""
    require_tools("ffmpeg")
    ffmpeg = shutil.which("ffmpeg")

    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-rtmp-")
    created = ivs.create_channel(
        name=name, latencyMode="NORMAL", type="STANDARD", tags={"purpose": "sim2real"}
    )
    channel_arn = created["channel"]["arn"]
    ingest_endpoint = created["channel"]["ingestEndpoint"]
    stream_key = created["streamKey"]["value"]

    deleted = {"done": False}

    def _cleanup_channel():
        if not deleted["done"]:
            try:
                ivs.delete_channel(arn=channel_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_channel)

    rtmps_url = f"{ctx.endpoint_url(ingest_endpoint, scheme='rtmps', aws_port=443)}/app/{stream_key}"
    proc = subprocess.Popen(
        [
            ffmpeg, "-re",
            "-f", "lavfi", "-i", "testsrc=duration=120:size=1280x720:rate=30",
            "-f", "lavfi", "-i", "sine=frequency=1000",
            "-pix_fmt", "yuv420p", "-profile:v", "baseline", "-level", "3.0",
            "-r", "30", "-g", "60", "-shortest",
            "-vcodec", "libx264", "-acodec", "aac",
            "-f", "flv", rtmps_url,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def _kill_ffmpeg():
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    ctx.on_cleanup(_kill_ffmpeg)

    try:
        stream = _poll_until_live(ctx, channel_arn, timeout_s=90)
        assert stream["state"] == "LIVE", f"expected stream state LIVE, got {stream['state']!r}"
        assert stream["channelArn"] == channel_arn, (
            f"GetStream returned channelArn {stream['channelArn']!r}, expected {channel_arn!r}"
        )

        # InsertAdBreak is not usable on a bare channel: AWS rejects it for a LIVE channel with no
        # ad configuration associated. Grade that precondition: an emulator that mints an
        # adBreakId for an unconfigured channel is unfaithful.
        try:
            ad_break = ivs.insert_ad_break(channelArn=channel_arn, durationSeconds=30)
        except ClientError as exc:
            err = exc.response["Error"]
            assert err.get("Code") == "ValidationException", (
                f"InsertAdBreak on a channel with no ad configuration should be rejected with "
                f"ValidationException, got {err.get('Code')!r}: {err.get('Message')!r}"
            )
            assert err.get("Message") == (
                "Request member: channelArn failed to satisfy the constraints: valid ad configuration is "
                "required to be associated with the channel requested for the ad break with ARN: "
                f"{channel_arn}"
            ), repr(err.get("Message"))
        else:
            raise AssertionError(
                "InsertAdBreak succeeded on a LIVE channel with no ad configuration associated "
                f"(returned {ad_break!r}); real AWS rejects this with ValidationException"
            )
        ivs.put_metadata(channelArn=channel_arn, metadata="sim2real-live-marker")

        # StopStream must run while the ingest is STILL PUSHING, which is the behaviour under
        # test: it forces a broadcasting channel offline. Killing ffmpeg first lets the channel
        # go offline on its own, and AWS then answers StopStream with ChannelNotBroadcasting.
        ivs.stop_stream(channelArn=channel_arn)
    finally:
        _kill_ffmpeg()

    error = _poll_until_not_broadcasting(ctx, channel_arn, timeout_s=60)
    assert error["Code"] == "ChannelNotBroadcasting", (
        f"expected ChannelNotBroadcasting after StopStream, got {error['Code']!r}"
    )
    assert error["Message"] == f"Channel: {channel_arn} is not currently online", repr(error["Message"])

    ivs.delete_channel(arn=channel_arn)
    deleted["done"] = True

    try:
        ivs.get_channel(arn=channel_arn)
        raise AssertionError("GetChannel succeeded after DeleteChannel on the RTMPS-tested channel")
    except ClientError as e:
        got_code = e.response["Error"]["Code"]
        assert got_code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException after DeleteChannel, got {got_code!r}"
        )
        got_msg = e.response["Error"]["Message"]
        assert got_msg == f"Resource: {channel_arn} not found", repr(got_msg)


def _poll_until_live(ctx, channel_arn, timeout_s=90.0, interval_s=2.0):
    ivs = ctx.client("ivs")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            stream = ivs.get_stream(channelArn=channel_arn)["stream"]
            if stream["state"] == "LIVE":
                return stream
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(f"stream never reached LIVE within {timeout_s}s (last error: {last_code})")


def _poll_until_not_broadcasting(ctx, channel_arn, timeout_s=60.0, interval_s=2.0):
    ivs = ctx.client("ivs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ivs.get_stream(channelArn=channel_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ChannelNotBroadcasting":
                return e.response["Error"]
            raise
        time.sleep(interval_s)
    raise AssertionError(f"channel never reported ChannelNotBroadcasting within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
