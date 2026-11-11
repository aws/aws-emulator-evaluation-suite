"""create-stream-negative-warm-throughput-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-negative-warm-throughput-rejected"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStream with a negative WarmThroughputMiBps fails input validation and creates no
    stream, while the identical on-demand create without it succeeds."""
    kinesis = ctx.client("kinesis")
    raw = _client_without_param_validation(ctx, "kinesis")

    rejected = ctx.unique_name("sim2real-behav-warmneg-")
    # A create that slipped through would bill; the cleanup is guarded and registered
    # before the call so a stream wrongly created despite the error is still removed.
    ctx.on_cleanup(lambda: _delete_stream(kinesis, rejected))
    code, message = _error(
        lambda: raw.create_stream(
            StreamName=rejected,
            StreamModeDetails={"StreamMode": "ON_DEMAND"},
            WarmThroughputMiBps=-1,
            Tags={"sim2real": CHECK},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected = (
        "1 validation error detected: Value '-1' at 'warmThroughputMiBps' failed to satisfy "
        "constraint: Member must have value greater than or equal to 0"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    absent_code, absent_message = _error(lambda: kinesis.describe_stream_summary(StreamName=rejected))
    assert absent_code == "ResourceNotFoundException", (
        f"expected the rejected stream to not exist, DescribeStreamSummary gave {absent_code!r}"
    )
    expected_absent = f"Stream {rejected} under account {ctx.account} not found."
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    accepted = ctx.unique_name("sim2real-behav-warmctl-")
    ctx.on_cleanup(lambda: _delete_stream(kinesis, accepted))
    kinesis.create_stream(
        StreamName=accepted, StreamModeDetails={"StreamMode": "ON_DEMAND"}, Tags={"sim2real": CHECK}
    )
    summary = _wait_stream_active(kinesis, accepted)
    mode = summary["StreamModeDetails"]["StreamMode"]
    assert mode == "ON_DEMAND", f"expected the control stream to be ON_DEMAND, got {mode!r}"


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
