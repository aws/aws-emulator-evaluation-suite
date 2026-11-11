"""get-clip-no-data-retention-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-clip-no-data-retention-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]

NO_RETENTION = ("NoDataRetentionException", "The stream data retention is set to 0 hours.")
NO_FRAGMENTS = ("ResourceNotFoundException", "No fragments found in the stream for the clip request.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetClip on a stream with DataRetentionInHours=0 fails with NoDataRetentionException while
    DescribeStream reports it ACTIVE, and after UpdateDataRetention raises retention the same call fails
    with ResourceNotFoundException."""
    kv = ctx.client("kinesisvideo")
    stream = _create_active_stream(ctx, retention_hours=0)
    clip = _archived_media_client(ctx, stream["name"], "GET_CLIP")

    def _clip_error():
        now = time.time()
        return _error(lambda: clip.get_clip(
            StreamName=stream["name"],
            ClipFragmentSelector={
                "FragmentSelectorType": "PRODUCER_TIMESTAMP",
                "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
            },
        ))

    err = _clip_error()
    assert err == NO_RETENTION, f"expected {NO_RETENTION!r}, got {err!r}"

    control = kv.describe_stream(StreamName=stream["name"])["StreamInfo"]
    assert control["Status"] == "ACTIVE", "positive control (DescribeStream) must still succeed"

    version = control["Version"]
    kv.update_data_retention(
        StreamName=stream["name"], CurrentVersion=version,
        Operation="INCREASE_DATA_RETENTION", DataRetentionChangeInHours=1,
    )
    _poll_until(
        lambda: kv.describe_stream(StreamName=stream["name"])["StreamInfo"]["DataRetentionInHours"],
        lambda h: h == 1, timeout_s=60, interval_s=3, description="DataRetentionInHours == 1",
    )

    # Control-plane (DescribeStream) can reflect the new retention before the data-plane (GetClip)
    # has propagated it, so poll GetClip's own error code rather than asserting on the first call.
    flipped = _poll_until(
        _clip_error, lambda e: e[0] != NO_RETENTION[0], timeout_s=90, interval_s=3,
        description="GetClip stops returning NoDataRetentionException once retention > 0",
    )
    assert flipped == NO_FRAGMENTS, (
        f"expected GetClip to fail on data-absence (ResourceNotFoundException) once retention > 0 "
        f"with no ingested fragments, got {flipped!r}"
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
    kv.tag_stream(StreamARN=arn, Tags={"sim2real": "true"})
    _wait_stream_active(kv, name)
    return {"name": name, "arn": arn}


def _archived_media_client(ctx, stream_name, api_name):
    kv = ctx.client("kinesisvideo")
    endpoint = kv.get_data_endpoint(StreamName=stream_name, APIName=api_name)["DataEndpoint"]
    return ctx.client("kinesis-video-archived-media", endpoint_url=endpoint)


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
