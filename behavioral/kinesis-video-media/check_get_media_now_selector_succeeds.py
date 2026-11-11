"""get-media-now-selector-succeeds."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-now-selector-succeeds"
GROUP = "data-plane"
SERVICES = ["kinesis-video-media"]

_MEDIA_CONFIG = Config(read_timeout=20, connect_timeout=10, retries={"max_attempts": 1})


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMedia with StartSelectorType=NOW opens a live-tail session (HTTP 200)
    against a stream that has never received any fragments -- NOW does not
    require any historical data to exist.
    """
    stream = _create_active_stream(ctx)
    media = _media_client_for(ctx, stream_name=stream["name"])

    resp = media.get_media(
        StreamName=stream["name"],
        StartSelector={"StartSelectorType": "NOW"},
    )

    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    content_type = resp["ContentType"]
    assert content_type == "video/webm", f"expected video/webm, got {content_type!r}"

    payload = resp["Payload"]
    try:
        data = payload.read()
    finally:
        payload.close()
    assert data == b"", (
        f"NOW on a stream that never received a fragment has nothing to tail; "
        f"expected an empty payload, got {len(data)} bytes"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_active_stream(ctx):
    control = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-behav-kvm-")
    stream_arn = control.create_stream(
        StreamName=name,
        DataRetentionInHours=1,
        Tags={"sim2real": CHECK},
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
