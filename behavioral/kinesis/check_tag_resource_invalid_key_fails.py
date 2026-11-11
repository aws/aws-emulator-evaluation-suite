"""tag-resource-invalid-key-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a reserved 'aws:'-prefixed tag key fails with InvalidArgumentException,
    the tag is never persisted, and a normal tag key still tags the resource successfully."""
    kinesis = ctx.client("kinesis")
    _stream_name, stream_arn = _create_stream(ctx)

    code, message = _error(
        lambda: kinesis.tag_resource(ResourceARN=stream_arn, Tags={"aws:reserved-behav-tag": "x"})
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected_message = "Some tag keys in the request started with 'aws:'. System tags cannot be modified."
    assert message == expected_message, (
        f"reserved-prefix TagResource message {message!r}, expected {expected_message!r}"
    )

    tags_after_bad = {
        t["Key"]: t["Value"] for t in kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    }
    assert "aws:reserved-behav-tag" not in tags_after_bad, "a reserved-prefix tag key must not be persisted"

    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"sim2real-behav-valid-tag": "ok"})
    tags_after_good = {
        t["Key"]: t["Value"] for t in kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    }
    got = tags_after_good.get("sim2real-behav-valid-tag")
    assert got == "ok", f"expected the non-reserved tag key to persist with value 'ok', got {got!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
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
    name = ctx.unique_name("sim2real-behav-kts-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
