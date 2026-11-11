"""get-images-width-height-pixels-accepted-on-empty-stream."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-images-width-height-pixels-accepted-on-empty-stream"
GROUP = "state"
SERVICES = ["kinesis-video-archived-media"]

NO_FRAGMENTS = ("ResourceNotFoundException", "No fragments found in the stream for the GetImages request.")
INCOMPLETE_RESIZE = ("InvalidArgumentException", "Height and width for the images need to be provided or none.")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetImages with both WidthPixels and HeightPixels on an empty stream fails only with
    ResourceNotFoundException for absent fragments, while WidthPixels alone fails with
    InvalidArgumentException and its exact message."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "GET_IMAGES")
    now = time.time()

    err = _error(lambda: media.get_images(
        StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
        StartTimestamp=now - 5, EndTimestamp=now, Format="JPEG",
        WidthPixels=320, HeightPixels=240,
    ))
    assert err == NO_FRAGMENTS, (
        f"expected {NO_FRAGMENTS!r} (resize params accepted, fragment absence still "
        f"surfaces), got {err!r}"
    )

    err_incomplete = _error(lambda: media.get_images(
        StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
        StartTimestamp=now - 5, EndTimestamp=now, Format="JPEG",
        WidthPixels=320,
    ))
    assert err_incomplete == INCOMPLETE_RESIZE, (
        f"expected InvalidArgumentException for WidthPixels without HeightPixels on the SAME "
        f"fragment-less stream (an incomplete resize pair rejected BEFORE the fragment-absence "
        f"check, distinct from the ResourceNotFoundException the complete pair gets above), "
        f"got {err_incomplete!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
