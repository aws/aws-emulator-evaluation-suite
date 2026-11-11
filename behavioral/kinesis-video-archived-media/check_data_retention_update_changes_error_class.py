"""data-retention-update-changes-error-class."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-retention-update-changes-error-class"
GROUP = "state"
SERVICES = ["kinesis-video-archived-media"]

NO_RETENTION = ("NoDataRetentionException", "The stream data retention is set to 0 hours.")
NO_FRAGMENTS = ("ResourceNotFoundException", "No fragments found in the stream for the clip request.")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetClip fails with NoDataRetentionException at retention 0, with ResourceNotFoundException (no
    fragments) after UpdateDataRetention raises it, and with NoDataRetentionException again after it is
    lowered back to 0."""
    kv = ctx.client("kinesisvideo")
    stream = _create_active_stream(ctx, retention_hours=0)
    clip = _archived_media_client(ctx, stream["name"], "GET_CLIP")

    now = time.time()
    err = _error(lambda: clip.get_clip(
        StreamName=stream["name"],
        ClipFragmentSelector={
            "FragmentSelectorType": "PRODUCER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
        },
    ))
    assert err == NO_RETENTION, f"expected {NO_RETENTION!r} at retention=0, got {err!r}"

    version = kv.describe_stream(StreamName=stream["name"])["StreamInfo"]["Version"]
    kv.update_data_retention(
        StreamName=stream["name"], CurrentVersion=version,
        Operation="INCREASE_DATA_RETENTION", DataRetentionChangeInHours=1,
    )
    _poll_until(
        lambda: kv.describe_stream(StreamName=stream["name"])["StreamInfo"]["DataRetentionInHours"],
        lambda h: h == 1, timeout_s=60, interval_s=3, description="DataRetentionInHours == 1",
    )

    # The control-plane (DescribeStream) can reflect the new retention before the data-plane
    # (GetClip) has propagated it, so poll GetClip's own error code to the expected transition
    # rather than asserting on the first call.
    def _clip_error():
        now = time.time()
        return _error(lambda: clip.get_clip(
            StreamName=stream["name"],
            ClipFragmentSelector={
                "FragmentSelectorType": "PRODUCER_TIMESTAMP",
                "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
            },
        ))

    err = _poll_until(
        _clip_error, lambda e: e[0] == NO_FRAGMENTS[0], timeout_s=90, interval_s=3,
        description="GetClip flips to ResourceNotFoundException once retention>0",
    )
    assert err == NO_FRAGMENTS, (
        f"expected {NO_FRAGMENTS!r} once retention>0 but no fragments exist, got {err!r}"
    )

    version = kv.describe_stream(StreamName=stream["name"])["StreamInfo"]["Version"]
    kv.update_data_retention(
        StreamName=stream["name"], CurrentVersion=version,
        Operation="DECREASE_DATA_RETENTION", DataRetentionChangeInHours=1,
    )
    _poll_until(
        lambda: kv.describe_stream(StreamName=stream["name"])["StreamInfo"]["DataRetentionInHours"],
        lambda h: h == 0, timeout_s=60, interval_s=3, description="DataRetentionInHours == 0",
    )

    err = _poll_until(
        _clip_error, lambda e: e[0] == NO_RETENTION[0], timeout_s=90, interval_s=3,
        description="GetClip flips back to NoDataRetentionException once retention==0",
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
        StreamName=name, DataRetentionInHours=retention_hours, MediaType="video/x-matroska",
        Tags={"sim2real": CHECK},
    )
    arn = resp["StreamARN"]
    ctx.on_cleanup(lambda: kv.delete_stream(StreamARN=arn))
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
