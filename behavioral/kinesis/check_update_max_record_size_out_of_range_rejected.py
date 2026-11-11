"""update-max-record-size-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-max-record-size-out-of-range-rejected"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMaxRecordSize outside the 1024-10240 KiB range is rejected with
    ValidationException, leaves MaxRecordSizeInKiB unchanged, and a subsequent
    in-range value still succeeds."""
    kinesis = ctx.client("kinesis")
    raw = _unvalidated_client(ctx, "kinesis")
    name = ctx.unique_name("sim2real-behav-maxrec-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, name)

    before = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    original_size = before.get("MaxRecordSizeInKiB")

    # Real AWS rejects the out-of-range value with a generic ValidationException
    # (schema range-constraint violation) rather than the domain-specific
    # InvalidArgumentException.
    code, message = _client_error(
        lambda: raw.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=20000)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '20000' at 'maxRecordSizeInKiB' failed to satisfy "
        "constraint: Member must have value less than or equal to 10240"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert after.get("MaxRecordSizeInKiB") == original_size, "MaxRecordSizeInKiB changed despite rejected request"

    kinesis.update_max_record_size(StreamARN=stream_arn, MaxRecordSizeInKiB=2048)
    final = _wait_max_record_size(ctx, name, 2048)
    assert final == 2048, f"expected MaxRecordSizeInKiB=2048 after a valid update, got {final!r}"


def _client_error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _unvalidated_client(ctx, service):
    """ctx.client with botocore's local parameter validation off, so a value the model forbids
    reaches the service instead of being rejected client-side."""
    return ctx.client(service, config=Config(parameter_validation=False))


def _wait_stream_active(ctx, name, timeout_s=120.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE")


def _wait_max_record_size(ctx, name, expected, timeout_s=60.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        last = desc.get("MaxRecordSizeInKiB")
        if desc["StreamStatus"] == "ACTIVE" and last == expected:
            return last
        time.sleep(2)
    raise AssertionError(f"MaxRecordSizeInKiB never reached {expected}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
