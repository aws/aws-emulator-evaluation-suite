"""native-rtmps-live-stream-lifecycle."""
from __future__ import annotations

import shutil
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "native-rtmps-live-stream-lifecycle"
GROUP = "native-protocol"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With an RTMPS stream pushed by ffmpeg, GetStream goes ChannelNotBroadcasting -> LIVE -> ChannelNotBroadcasting
    around StopStream, while InsertAdBreak without an ad configuration fails with the same ValidationException
    before, during and after the broadcast."""

    require_tools("ffmpeg")
    ffmpeg = shutil.which("ffmpeg")

    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-native-")
    created = ivs.create_channel(name=name, tags={"sim2real-check": CHECK})
    channel = created["channel"]
    stream_key = created["streamKey"]["value"]
    channel_arn = channel["arn"]
    ingest_endpoint = channel["ingestEndpoint"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))
    offline_msg = f"Channel: {channel_arn} is not currently online"
    no_ad_config_msg = (
        "Request member: channelArn failed to satisfy the constraints: valid ad configuration is "
        "required to be associated with the channel requested for the ad break with ARN: "
        f"{channel_arn}"
    )

    # Before any ingest, the channel is not broadcasting.
    code, msg = _expect_error(lambda: ivs.get_stream(channelArn=channel_arn), "GetStream before ingest")
    assert code == "ChannelNotBroadcasting", f"expected ChannelNotBroadcasting before any ingest, got {code!r}"
    assert msg == offline_msg, repr(msg)

    # InsertAdBreak requires a valid ad configuration on the channel, checked unconditionally
    # -- confirmed by replay to fire identically before ingest, while genuinely LIVE, and after
    # StopStream (see below), i.e. it is gated by this precondition rather than by broadcast
    # state. The message names the missing precondition, not a generic validation failure, so
    # this cannot be confused with "rejects every InsertAdBreak".
    code2, msg2 = _expect_error(
        lambda: ivs.insert_ad_break(channelArn=channel_arn, durationSeconds=6),
        "InsertAdBreak before ingest",
    )
    assert code2 == "ValidationException", f"expected ValidationException (no ad configuration), got {code2!r}"
    assert msg2 == no_ad_config_msg, repr(msg2)

    rtmps_url = f"{ctx.endpoint_url(ingest_endpoint, scheme='rtmps', aws_port=443)}/app/{stream_key}"
    proc = subprocess.Popen(
        [
            ffmpeg,
            "-re",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=640x480:rate=15",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=1000",
            "-pix_fmt",
            "yuv420p",
            "-profile:v",
            "baseline",
            "-level",
            "3.0",
            "-r",
            "15",
            "-g",
            "30",
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-c:a",
            "aac",
            "-f",
            "flv",
            "-t",
            "180",
            rtmps_url,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ctx.on_cleanup(lambda: _kill(proc))

    try:
        stream = _poll_until(
            ctx,
            probe=lambda: _get_stream_state(ivs, channel_arn),
            predicate=lambda s: s == "LIVE",
            timeout_s=90.0,
            interval_s=3.0,
        )
        assert stream == "LIVE", f"expected the polled stream state to be LIVE, got {stream!r}"

        # Same ad-configuration precondition, same ValidationException, even though the
        # channel is now genuinely LIVE -- the precondition is unconditional, not state-gated.
        live_code, live_msg = _expect_error(
            lambda: ivs.insert_ad_break(channelArn=channel_arn, durationSeconds=6),
            "InsertAdBreak while LIVE (no ad configuration)",
        )
        assert live_code == "ValidationException", f"expected ValidationException (no ad configuration), got {live_code!r}"
        assert live_msg == no_ad_config_msg, repr(live_msg)

        # PutMetadata carries no such precondition, so it is the operation that actually
        # demonstrates state-gated success while LIVE.
        ivs.put_metadata(channelArn=channel_arn, metadata="sim2real-native-check")

        ivs.stop_stream(channelArn=channel_arn)

        # After StopStream forces the ingest down, GetStream reverts to not broadcasting --
        # the same operation that succeeded above now fails deterministically in the new state.
        def _stopped() -> bool:
            # Tolerant probe: while the ingest connection is still draining, GetStream may
            # legitimately keep succeeding for a few seconds, so a success here is a transient
            # "not yet" rather than a defect -- unlike the terminal checks below.
            from botocore.exceptions import ClientError

            try:
                ivs.get_stream(channelArn=channel_arn)
            except ClientError as e:
                return e.response["Error"]["Code"] == "ChannelNotBroadcasting"
            return False

        stopped = _poll_until(ctx, probe=_stopped, predicate=lambda v: v, timeout_s=60.0, interval_s=3.0)
        assert stopped is True, "channel never reverted to ChannelNotBroadcasting after StopStream"
        stopped_code, stopped_msg = _expect_error(
            lambda: ivs.get_stream(channelArn=channel_arn), "GetStream after StopStream"
        )
        assert stopped_code == "ChannelNotBroadcasting", (
            f"expected ChannelNotBroadcasting after StopStream, got {stopped_code!r}"
        )
        assert stopped_msg == offline_msg, repr(stopped_msg)

        # InsertAdBreak carries the same ad-configuration ValidationException a third time,
        # now that broadcasting has genuinely stopped -- consistent across all three states.
        after_code, after_msg = _expect_error(
            lambda: ivs.insert_ad_break(channelArn=channel_arn, durationSeconds=6),
            "InsertAdBreak after StopStream",
        )
        assert after_code == "ValidationException", f"expected ValidationException (no ad configuration), got {after_code!r}"
        assert after_msg == no_ad_config_msg, repr(after_msg)
    finally:
        _kill(proc)


def _expect_error(fn, description):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"{description}: expected a ClientError but the call succeeded with {result!r}")


def _get_stream_state(ivs, channel_arn: str):
    from botocore.exceptions import ClientError

    try:
        return ivs.get_stream(channelArn=channel_arn)["stream"]["state"]
    except ClientError:
        return None


def _poll_until(ctx, probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
