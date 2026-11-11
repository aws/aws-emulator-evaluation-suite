"""get-media-by-stream-arn-succeeds."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-by-stream-arn-succeeds"
GROUP = "data-plane"
SERVICES = ["kinesis-video-media"]

_MEDIA_CONFIG = Config(read_timeout=20, connect_timeout=10, retries={"max_attempts": 1})


@tags("axis:happy-path", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMedia accepts StreamARN as an equivalent identifier to StreamName --
    both GetDataEndpoint and GetMedia succeed when addressed purely by ARN.
    """
    stream = _create_active_stream(ctx)
    media = _media_client_for(ctx, stream_arn=stream["arn"])

    resp = media.get_media(
        StreamARN=stream["arn"],
        StartSelector={"StartSelectorType": "EARLIEST"},
    )

    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected GetMedia(StreamARN=...) to return 200, got {status}"
    content_type = resp["ContentType"]
    assert isinstance(content_type, str) and len(content_type) > 0, (
        f"expected a non-empty ContentType header, got {content_type!r}"
    )

    payload = resp["Payload"]
    try:
        data = payload.read()
    finally:
        payload.close()
    assert isinstance(data, bytes), f"expected the Payload stream to read as bytes, got {type(data)!r}"


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
        StreamName=name, DataRetentionInHours=1, Tags={"sim2real": "true"}
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
