"""get-images-timestamp-window-exceeds-300-seconds-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-images-timestamp-window-exceeds-300-seconds-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]

WINDOW_TOO_WIDE = ("InvalidArgumentException", "EndTimestamp must be within 300 seconds of StartTimestamp.")
NO_FRAGMENTS = ("ResourceNotFoundException", "No fragments found in the stream for the GetImages request.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetImages with a window wider than 300 seconds fails with InvalidArgumentException and its exact
    message, while a window of at most 300 seconds on the same empty stream fails with
    ResourceNotFoundException."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "GET_IMAGES")
    now = time.time()

    err_wide = _error(lambda: media.get_images(
        StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
        StartTimestamp=now - 1800, EndTimestamp=now, Format="JPEG",
    ))
    assert err_wide == WINDOW_TOO_WIDE, (
        f"expected {WINDOW_TOO_WIDE!r} for a >300s window, got {err_wide!r}"
    )

    err_narrow = _error(lambda: media.get_images(
        StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
        StartTimestamp=now - 10, EndTimestamp=now, Format="JPEG",
    ))
    assert err_narrow == NO_FRAGMENTS, (
        f"expected a <=300s window on the same fragment-less stream to fail differently "
        f"(ResourceNotFoundException, not InvalidArgumentException), got {err_narrow!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
