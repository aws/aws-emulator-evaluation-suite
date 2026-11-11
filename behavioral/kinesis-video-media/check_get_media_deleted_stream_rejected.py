"""get-media-deleted-stream-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-deleted-stream-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-media"]

_MEDIA_CONFIG = Config(read_timeout=20, connect_timeout=10, retries={"max_attempts": 1})


@tags("axis:rejection", "cap:c1", "cap:c4", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After DeleteStream completes, GetMedia for the stream fails with ResourceNotFoundException "The
    requested stream is not found or not active.", while GetMedia returns 200 for it before and for a live
    stream after."""
    control = ctx.client("kinesisvideo")
    stream = _create_active_stream(ctx)
    media = _media_client_for(ctx, stream_name=stream["name"])

    # Confirm the stream is actually readable before we tear it down.
    pre_resp = media.get_media(
        StreamName=stream["name"],
        StartSelector={"StartSelectorType": "EARLIEST"},
    )
    pre_status = pre_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert pre_status == 200, f"expected 200 from GetMedia on live stream, got {pre_status}"
    pre_resp["Payload"].close()

    control.delete_stream(StreamARN=stream["arn"])
    _wait_until_deleted(control, stream["name"])

    err = _error(
        lambda: media.get_media(
            StreamName=stream["name"],
            StartSelector={"StartSelectorType": "EARLIEST"},
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    assert err["Message"] == (
        "The requested stream is not found or not active."
    ), f"unexpected ResourceNotFoundException message: {err['Message']!r}"

    # Positive control: a fresh, still-live sibling stream is unaffected.
    sibling = _create_active_stream(ctx)
    sibling_media = _media_client_for(ctx, stream_name=sibling["name"])
    control_resp = sibling_media.get_media(
        StreamName=sibling["name"],
        StartSelector={"StartSelectorType": "EARLIEST"},
    )
    sibling_status = control_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert sibling_status == 200, (
        f"expected 200 from GetMedia on unaffected sibling stream, got {sibling_status}"
    )
    control_resp["Payload"].close()


def _error(fn):
    """The ClientError's ``Error`` member; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_until_deleted(control, name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            control.describe_stream(StreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} was not deleted within {timeout_s}s")


def _create_active_stream(ctx):
    control = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-behav-kvm-")
    stream_arn = control.create_stream(
        StreamName=name, DataRetentionInHours=1, Tags={"sim2real": "1"}
    )["StreamARN"]

    def _cleanup():
        try:
            control.delete_stream(StreamARN=stream_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: control.describe_stream(StreamName=name)["StreamInfo"]["Status"],
        lambda status: status == "ACTIVE",
    )
    return {"name": name, "arn": stream_arn}


def _media_client_for(ctx, stream_name=None, stream_arn=None, api_name="GET_MEDIA"):
    control = ctx.client("kinesisvideo")
    kwargs = {"APIName": api_name}
    if stream_arn:
        kwargs["StreamARN"] = stream_arn
    else:
        kwargs["StreamName"] = stream_name
    endpoint = control.get_data_endpoint(**kwargs)["DataEndpoint"]
    return ctx.client(
        "kinesis-video-media", endpoint_url=ctx.endpoint_url(endpoint), config=_MEDIA_CONFIG
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
