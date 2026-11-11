"""update-max-record-size-exceeding-service-cap-must-fail."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-max-record-size-exceeding-service-cap-must-fail"
GROUP = "overly-permissive"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMaxRecordSize above the 10240 KiB ceiling fails with ValidationException instead of
    clamping and leaves MaxRecordSizeInKiB unchanged; an in-range value then succeeds and
    persists."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-maxrecsize-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    stream_arn = _wait_stream_active(ctx, stream_name)

    before = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
    original_size = before.get("MaxRecordSizeInKiB")

    code, message = _error_code(
        lambda: kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=10241)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for MaxRecordSizeInKiB=10241 (above the 10240 ceiling), got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value '10241' at 'maxRecordSizeInKiB' failed to satisfy "
        "constraint: Member must have value less than or equal to 10240"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
    assert after["StreamStatus"] == "ACTIVE", f"expected ACTIVE after rejected update, got {after['StreamStatus']!r}"
    assert after.get("MaxRecordSizeInKiB") == original_size, (
        f"MaxRecordSizeInKiB must stay at pre-call value {original_size!r} after rejection, "
        f"got {after.get('MaxRecordSizeInKiB')!r}"
    )

    # positive control: a value inside the 1024-10240 range succeeds and persists
    target_size = 2048 if original_size != 2048 else 4096
    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=target_size)
    final_size = _wait_for_max_record_size(ctx, stream_name, target_size)
    assert final_size == target_size, f"expected MaxRecordSizeInKiB to persist as {target_size}, got {final_size!r}"


def _error_code(fn):
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE")


def _wait_for_max_record_size(ctx, stream_name: str, want: int, timeout_s: float = 60.0) -> int:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    size = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        size = summary.get("MaxRecordSizeInKiB")
        if summary["StreamStatus"] == "ACTIVE" and size == want:
            return size
        time.sleep(3)
    raise AssertionError(f"MaxRecordSizeInKiB never reached {want}, last seen {size!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
