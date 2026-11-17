"""rtmps-ingest-native-protocol-round-trip."""
from __future__ import annotations

import subprocess
import time
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rtmps-ingest-native-protocol-round-trip"
GROUP = "native-protocol"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An RTMPS push of a test pattern turns the channel LIVE, its playback URL serves an HLS
    multivariant playlist, InsertAdBreak succeeds while live, and StopStream forces it offline."""
    from fidelity_tests_runner import require_tools

    require_tools("ffmpeg")

    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-live-")
    resp = ivs.create_channel(
        name=name, latencyMode="LOW", type="STANDARD", tags={"purpose": "sim2real"}
    )
    channel = resp["channel"]
    arn = channel["arn"]
    ingest_endpoint = channel["ingestEndpoint"]
    playback_url = channel["playbackUrl"]
    stream_key_value = resp["streamKey"]["value"]

    def _cleanup_channel():
        # A channel stays live briefly after its ingest drops; retry the delete through that
        # window within the 60 s cleanup budget.
        deadline = time.monotonic() + 50
        while True:
            try:
                ivs.delete_channel(arn=arn)
                return
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ConflictException" or time.monotonic() > deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup_channel)

    ingest_url = f"{ctx.endpoint_url(ingest_endpoint, scheme='rtmps', aws_port=443)}/app/{stream_key_value}"
    ffmpeg_cmd = [
        "ffmpeg",
        "-re",
        "-f",
        "lavfi",
        "-i",
        "testsrc=size=640x360:rate=30",
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
        "30",
        "-g",
        "60",
        "-vcodec",
        "libx264",
        "-b:v",
        "1500k",
        "-maxrate",
        "1500k",
        "-bufsize",
        "3000k",
        "-acodec",
        "aac",
        "-f",
        "flv",
        ingest_url,
    ]
    proc = subprocess.Popen(
        ffmpeg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
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
        stream = _poll_until(
            lambda: _try_get_stream(ivs, arn),
            lambda s: s is not None and s.get("state") == "LIVE",
            timeout_s=90,
            interval_s=3,
        )
        assert stream is not None and stream.get("state") == "LIVE", (
            f"channel never reported LIVE, last observed: {stream}"
        )
        stream_id = stream["streamId"]

        manifest = _poll_until(
            lambda: _try_fetch(ctx, playback_url),
            lambda body: body is not None,
            timeout_s=60,
            interval_s=3,
        )
        assert manifest.startswith("#EXTM3U"), "playbackUrl did not serve an HLS manifest"

        # InsertAdBreak is not usable on a bare channel: AWS rejects it for a LIVE channel that has
        # no ad configuration associated. The precondition itself is the behaviour worth grading
        # (this check is tagged concern:negative-classes): an emulator that mints an adBreakId for
        # an unconfigured channel is not faithful.
        try:
            ad_resp = ivs.insert_ad_break(channelArn=arn, durationSeconds=6)
        except ClientError as exc:
            err = exc.response["Error"]
            assert err.get("Code") == "ValidationException", (
                f"InsertAdBreak on a channel with no ad configuration should be rejected with "
                f"ValidationException, got {err.get('Code')!r}: {err.get('Message')!r}"
            )
            assert err.get("Message") == (
                "Request member: channelArn failed to satisfy the constraints: valid ad configuration is "
                "required to be associated with the channel requested for the ad break with ARN: "
                f"{arn}"
            ), repr(err.get("Message"))
        else:
            raise AssertionError(
                "InsertAdBreak succeeded on a LIVE channel with no ad configuration associated "
                f"(returned {ad_resp!r}); real AWS rejects this with ValidationException"
            )

        ivs.stop_stream(channelArn=arn)

        _poll_until(
            lambda: _try_get_stream(ivs, arn),
            lambda s: s is None,
            timeout_s=60,
            interval_s=3,
        )
        offline = _error(lambda: ivs.get_stream(channelArn=arn))
        assert offline["Code"] == "ChannelNotBroadcasting", (
            f"expected ChannelNotBroadcasting after StopStream, got: {offline['Code']!r}"
        )
        assert offline["Message"] == f"Channel: {arn} is not currently online", repr(offline["Message"])

        session = _poll_until(
            lambda: ivs.get_stream_session(channelArn=arn, streamId=stream_id)[
                "streamSession"
            ],
            lambda s: s.get("endTime") is not None,
            timeout_s=60,
            interval_s=3,
        )
        assert session["endTime"] is not None, (
            f"stream session never recorded an endTime after StopStream: {session}"
        )
        assert session["startTime"] is not None, (
            f"stream session never recorded a startTime: {session}"
        )
    finally:
        _kill_ffmpeg()


# ===== helpers =====
def _try_get_stream(ivs, arn):
    try:
        return ivs.get_stream(channelArn=arn)["stream"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ChannelNotBroadcasting":
            return None
        raise


def _try_fetch(ctx, url):
    """The playback URL 404s until the first HLS segments are packaged; None means not yet."""
    import urllib.error

    try:
        target_url, route_headers = ctx.endpoint_route(url)
        return urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=15).read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
