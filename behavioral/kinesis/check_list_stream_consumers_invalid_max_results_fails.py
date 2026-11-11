"""list-stream-consumers-invalid-max-results-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-stream-consumers-invalid-max-results-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStreamConsumers with MaxResults above 10000 fails server-side with ValidationException
    and its exact message instead of being clamped, while an in-range MaxResults succeeds."""
    _stream_name, stream_arn = _create_stream(ctx)
    raw = _raw_client(ctx, "kinesis")

    error = _client_error(lambda: raw.list_stream_consumers(StreamARN=stream_arn, MaxResults=10001))
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for an out-of-range MaxResults, got {error.get('Code')}"
    )
    expected_message = (
        "1 validation error detected: Value '10001' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 10000"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    ok = raw.list_stream_consumers(StreamARN=stream_arn, MaxResults=100)
    assert "Consumers" in ok, f"expected an in-range MaxResults to succeed with a Consumers list, got {ok!r}"


def _client_error(fn):
    """The botocore Error dict ``fn`` raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_stream_active(kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _create_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-klc-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


def _raw_client(ctx, service):
    """A ctx client with botocore's client-side parameter validation disabled, so out-of-range
    values reach the service instead of being rejected locally."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
