"""update-max-record-size-exceeds-service-ceiling-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-max-record-size-exceeds-service-ceiling-rejected"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMaxRecordSize above the 10240 KiB ceiling fails with ValidationException and leaves
    MaxRecordSizeInKiB unchanged; an in-range value (5120) is then accepted."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-maxrecsize-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))
    summary = _wait_stream_active(kinesis, stream_name)
    stream_arn = summary["StreamARN"]
    before_size = summary.get("MaxRecordSizeInKiB")

    code, message = _client_error(
        lambda: kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=20000)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '20000' at 'maxRecordSizeInKiB' failed to satisfy "
        "constraint: Member must have value less than or equal to 10240"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_bad = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"]
    assert after_bad.get("MaxRecordSizeInKiB") == before_size

    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=5120)
    updated = _wait_stream_active(kinesis, stream_name)
    assert updated["MaxRecordSizeInKiB"] == 5120


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE, last={summary}")


def _client_error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_stream(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
