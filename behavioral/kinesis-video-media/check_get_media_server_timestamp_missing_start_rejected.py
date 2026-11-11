"""get-media-server-timestamp-missing-start-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-server-timestamp-missing-start-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis-video-media"]

_MEDIA_CONFIG = Config(read_timeout=20, connect_timeout=10, retries={"max_attempts": 1})


@tags("axis:rejection", "cap:c1", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSelectorType=SERVER_TIMESTAMP without the required StartTimestamp
    field is rejected with InvalidArgumentException; a normal EARLIEST call
    against the same stream (positive control) still succeeds.
    """
    stream = _create_active_stream(ctx)
    media = _media_client_for(ctx, stream_name=stream["name"])

    err = _error(
        lambda: media.get_media(
            StreamName=stream["name"],
            StartSelector={"StartSelectorType": "SERVER_TIMESTAMP"},
        )
    )
    assert err["Code"] == "InvalidArgumentException", f"expected InvalidArgumentException, got {err!r}"
    assert err["Message"] == (
        "Start Timestamp must be specified for StartSelector : StartSelector(startSelectorType="
        "SERVER_TIMESTAMP, afterFragmentNumber=null, startTimestamp=null, continuationToken=null)"
    ), f"unexpected InvalidArgumentException message: {err['Message']!r}"

    control_resp = media.get_media(
        StreamName=stream["name"],
        StartSelector={"StartSelectorType": "EARLIEST"},
    )
    status = control_resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected positive-control EARLIEST call to succeed with 200, got {status}"
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


def _create_active_stream(ctx):
    control = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-behav-kvm-")
    stream_arn = control.create_stream(
        StreamName=name, DataRetentionInHours=1, Tags={"sim2real-check": CHECK}
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
