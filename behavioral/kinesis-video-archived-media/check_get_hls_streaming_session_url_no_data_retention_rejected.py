"""get-hls-streaming-session-url-no-data-retention-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-hls-streaming-session-url-no-data-retention-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]

NO_RETENTION = ("NoDataRetentionException", "The stream data retention is set to 0 hours.")
NO_FRAGMENTS = ("ResourceNotFoundException", "No fragments found in the stream for the streaming request.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetHLSStreamingSessionURL on a stream with retention 0 fails with NoDataRetentionException while
    DescribeStream reports ACTIVE; raising retention changes it to ResourceNotFoundException and lowering
    it back restores the first error."""
    kv = ctx.client("kinesisvideo")
    stream = _create_active_stream(ctx, retention_hours=0)
    hls = _archived_media_client(ctx, stream["name"], "GET_HLS_STREAMING_SESSION_URL")

    def _hls_error():
        now = time.time()
        return _error(lambda: hls.get_hls_streaming_session_url(
            StreamName=stream["name"],
            PlaybackMode="ON_DEMAND",
            HLSFragmentSelector={
                "FragmentSelectorType": "SERVER_TIMESTAMP",
                "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
            },
        ))

    err = _hls_error()
    assert err == NO_RETENTION, f"expected {NO_RETENTION!r}, got {err!r}"

    control = kv.describe_stream(StreamName=stream["name"])["StreamInfo"]
    assert control["Status"] == "ACTIVE", "positive control (DescribeStream) must still succeed"

    _update_retention(kv, stream["name"], "INCREASE_DATA_RETENTION", 1)
    _poll_until(
        lambda: kv.describe_stream(StreamName=stream["name"])["StreamInfo"]["DataRetentionInHours"],
        lambda h: h == 1, timeout_s=60, interval_s=3, description="DataRetentionInHours == 1",
    )
    err = _poll_until(
        _hls_error, lambda e: e[0] == NO_FRAGMENTS[0], timeout_s=90, interval_s=3,
        description="GetHLSStreamingSessionURL flips to ResourceNotFoundException once retention>0",
    )
    assert err == NO_FRAGMENTS, (
        f"expected {NO_FRAGMENTS!r} once retention>0 but no fragments exist, got {err!r}"
    )

    _update_retention(kv, stream["name"], "DECREASE_DATA_RETENTION", 1)
    _poll_until(
        lambda: kv.describe_stream(StreamName=stream["name"])["StreamInfo"]["DataRetentionInHours"],
        lambda h: h == 0, timeout_s=60, interval_s=3, description="DataRetentionInHours == 0",
    )
    err = _poll_until(
        _hls_error, lambda e: e[0] == NO_RETENTION[0], timeout_s=90, interval_s=3,
        description="GetHLSStreamingSessionURL flips back to NoDataRetentionException once retention==0",
    )
    assert err == NO_RETENTION, (
        f"expected {NO_RETENTION!r} again after decreasing back to 0, got {err!r}"
    )


def _error(fn):
    """The (code, message) AWS refuses ``fn`` with; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_stream_active(kv, name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_stream(StreamName=name)["StreamInfo"]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} never reached ACTIVE (last status={status})")


def _create_active_stream(ctx, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvam-")
    resp = kv.create_stream(
        StreamName=name, DataRetentionInHours=retention_hours, MediaType="video/x-matroska"
    )
    arn = resp["StreamARN"]
    ctx.on_cleanup(lambda: kv.delete_stream(StreamARN=arn))
    _wait_stream_active(kv, name)
    return {"name": name, "arn": arn}


def _archived_media_client(ctx, stream_name, api_name):
    kv = ctx.client("kinesisvideo")
    endpoint = kv.get_data_endpoint(StreamName=stream_name, APIName=api_name)["DataEndpoint"]
    return ctx.client("kinesis-video-archived-media", endpoint_url=endpoint)


def _update_retention(kv, name, operation, hours):
    version = kv.describe_stream(StreamName=name)["StreamInfo"]["Version"]
    kv.update_data_retention(
        StreamName=name, CurrentVersion=version,
        Operation=operation, DataRetentionChangeInHours=hours,
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
