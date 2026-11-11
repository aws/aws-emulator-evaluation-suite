"""get-images-reversed-timestamp-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-images-reversed-timestamp-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]

REVERSED = ("InvalidArgumentException", "StartTimestamp must be before EndTimestamp.")
NO_FRAGMENTS = ("ResourceNotFoundException", "No fragments found in the stream for the GetImages request.")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetImages with StartTimestamp after EndTimestamp fails with InvalidArgumentException and its exact
    message, the same timestamps in order fail with ResourceNotFoundException, and ListFragments returns an
    empty list."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "GET_IMAGES")
    fragments = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")
    now = time.time()

    err = _error(lambda: media.get_images(
        StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
        StartTimestamp=now, EndTimestamp=now - 60, Format="JPEG",
    ))
    assert err == REVERSED, f"expected {REVERSED!r}, got {err!r}"

    err_ordered = _error(lambda: media.get_images(
        StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
        StartTimestamp=now - 60, EndTimestamp=now, Format="JPEG",
    ))
    assert err_ordered == NO_FRAGMENTS, (
        f"expected the identical call with a correctly-ordered range on the same fragment-less "
        f"stream to fail differently (ResourceNotFoundException, not InvalidArgumentException), "
        f"got {err_ordered!r}"
    )

    control = fragments.list_fragments(
        StreamName=stream["name"],
        FragmentSelector={
            "FragmentSelectorType": "SERVER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
        },
    )
    assert control["Fragments"] == [], "positive control (ListFragments) must still succeed"


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
        Tags={"sim2real-check": CHECK},
    )
    arn = resp["StreamARN"]
    ctx.on_cleanup(lambda: kv.delete_stream(StreamARN=arn))
    _wait_stream_active(kv, name)
    return {"name": name, "arn": arn}


def _archived_media_client(ctx, stream_name, api_name):
    kv = ctx.client("kinesisvideo")
    endpoint = kv.get_data_endpoint(StreamName=stream_name, APIName=api_name)["DataEndpoint"]
    return ctx.client("kinesis-video-archived-media", endpoint_url=endpoint)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
