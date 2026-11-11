"""update-stream-mode-invalid-mode-value-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-stream-mode-invalid-mode-value-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStreamMode with an unrecognized StreamMode value fails with
    ValidationException instead of silently defaulting to some mode, the stream's actual
    capacity mode is left untouched, and switching to a real, valid mode still succeeds."""
    kinesis = ctx.client("kinesis")
    _stream_name, stream_arn = _create_stream(ctx, mode="ON_DEMAND")

    before = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"][
        "StreamModeDetails"
    ]["StreamMode"]
    assert before == "ON_DEMAND", f"expected the freshly created stream to be ON_DEMAND, got {before}"

    code, message = _error_code(
        lambda: kinesis.update_stream_mode(StreamARN=stream_arn, StreamModeDetails={"StreamMode": "BOGUS_MODE"})
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an unrecognized StreamMode, got {code}"
    )
    expected_message = (
        "1 validation error detected: Value 'BOGUS_MODE' at 'streamModeDetails.streamMode' "
        "failed to satisfy constraint: Member must satisfy enum value set: [ON_DEMAND, PROVISIONED]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_bad = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"][
        "StreamModeDetails"
    ]["StreamMode"]
    assert after_bad == "ON_DEMAND", "an invalid StreamMode value must not change the stream's capacity mode"

    kinesis.update_stream_mode(StreamARN=stream_arn, StreamModeDetails={"StreamMode": "PROVISIONED"})
    _wait_stream_mode(kinesis, stream_arn, "PROVISIONED")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_stream_active(kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _wait_stream_mode(kinesis, stream_arn, expected, timeout_s=240.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE" and summary["StreamModeDetails"]["StreamMode"] == expected:
            return
        time.sleep(5)
    raise AssertionError(f"stream mode for {stream_arn} never became {expected}")


def _create_stream(ctx, mode="ON_DEMAND"):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kmd-")
    kinesis.create_stream(
        StreamName=name, StreamModeDetails={"StreamMode": mode}, Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
