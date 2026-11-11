"""get-media-malformed-stream-arn-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-malformed-stream-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis-video-media"]

_MEDIA_CONFIG = Config(read_timeout=20, connect_timeout=10, retries={"max_attempts": 1})


@tags("axis:rejection", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMedia with a StreamARN outside the documented ARN pattern fails with ValidationException and its
    exact pattern message, while an EARLIEST call with the stream's real ARN returns 200."""
    stream = _create_active_stream(ctx)
    media = _media_client_for(ctx, stream_arn=stream["arn"])

    code, message = _error(
        lambda: media.get_media(
            StreamARN="arn:aws:not-a-real-service:us-east-1:123456789012:whatever",
            StartSelector={"StartSelectorType": "EARLIEST"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value at 'streamARN' failed to satisfy constraint: Member must "
        "satisfy regular expression pattern: "
        "arn:[a-z\\d-]+:kinesisvideo:[a-z0-9-]+:[0-9]+:[a-z]+/[a-zA-Z0-9_.-]+/[0-9]+"
    ), f"GetMedia message: {message!r}"

    control_resp = media.get_media(
        StreamARN=stream["arn"],
        StartSelector={"StartSelectorType": "EARLIEST"},
    )
    status = control_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected positive control to succeed with 200, got {status!r}"
    control_resp["Payload"].close()


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


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
        Tags={"sim2real-check": CHECK},
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
