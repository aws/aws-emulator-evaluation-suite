"""update-max-record-size-out-of-range-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-max-record-size-out-of-range-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMaxRecordSize below the 1024 KiB minimum fails with ValidationException and leaves
    MaxRecordSizeInKiB unchanged; an in-range value (2048) still applies."""
    _stream_name, stream_arn = _create_stream(ctx)
    raw = _raw_client(ctx, "kinesis")
    kinesis = ctx.client("kinesis")

    before = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"][
        "MaxRecordSizeInKiB"
    ]

    code, message = _error_code(lambda: raw.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=100))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "1 validation error detected: Value '100' at 'maxRecordSizeInKiB' failed to satisfy "
        "constraint: Member must have value greater than or equal to 1024"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_bad = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"][
        "MaxRecordSizeInKiB"
    ]
    assert after_bad == before, "an out-of-range MaxRecordSizeInKiB must not be applied"

    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=2048)
    _wait_max_record_size(kinesis, stream_arn, 2048)


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_stream_active(kinesis, stream_name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _wait_max_record_size(kinesis, stream_arn, expected, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE" and summary["MaxRecordSizeInKiB"] == expected:
            return
        time.sleep(3)
    raise AssertionError(f"MaxRecordSizeInKiB for {stream_arn} never became {expected}")


def _create_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kmr-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
        ShardCount=1,
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


def _raw_client(ctx, service):
    """ctx.client with botocore's local parameter validation off, so an out-of-range value
    reaches the service instead of being rejected client-side."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
