"""update-stream-warm-throughput-negative-value-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stream-warm-throughput-negative-value-rejected"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStreamWarmThroughput with a negative value on an active on-demand stream fails input
    validation and leaves the stream ACTIVE in on-demand mode."""
    kinesis = ctx.client("kinesis")
    raw = _client_without_param_validation(ctx, "kinesis")

    name = ctx.unique_name("sim2real-behav-warmupd-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: _delete_stream(kinesis, name))
    before = _wait_stream_active(kinesis, name)
    arn = before["StreamARN"]

    code, message = _error(
        lambda: raw.update_stream_warm_throughput(StreamARN=arn, WarmThroughputMiBps=-1)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected = (
        "1 validation error detected: Value '-1' at 'warmThroughputMiBps' failed to satisfy "
        "constraint: Member must have value greater than or equal to 0"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = kinesis.describe_stream_summary(StreamARN=arn)["StreamDescriptionSummary"]
    assert after["StreamStatus"] == "ACTIVE", (
        f"expected the stream to stay ACTIVE after the rejected update, got {after['StreamStatus']!r}"
    )
    assert after["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f"expected ON_DEMAND after the rejected update, got {after['StreamModeDetails']!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _client_without_param_validation(ctx, service: str):
    """ctx.client with botocore's local parameter validation off, so a value the model forbids
    reaches the service instead of being rejected client-side."""
    return ctx.client(service, config=Config(parameter_validation=False, retries={"max_attempts": 1}))


def _wait_stream_active(kinesis, name: str, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE, last={summary!r}")


def _delete_stream(kinesis, name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
