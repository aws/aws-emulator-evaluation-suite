"""tag-resource-reserved-aws-prefix-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a reserved 'aws:' key prefix fails with InvalidArgumentException and is
    not stored, while a normal tag key on the same stream is accepted and listed."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-tagprefix-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    stream_arn = _wait_stream_active(ctx, stream_name)

    code, message = _client_error(
        lambda: kinesis.tag_resource(
            ResourceARN=stream_arn, Tags={"aws:sim2real-behav": "blocked"}
        )
    )
    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException for a reserved 'aws:' tag key, got {code!r}"
    )
    expected_message = "Some tag keys in the request started with 'aws:'. System tags cannot be modified."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tags_after = {
        t["Key"]: t["Value"]
        for t in kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    }
    assert "aws:sim2real-behav" not in tags_after, (
        f"rejected 'aws:sim2real-behav' tag must not be persisted, saw {tags_after!r}"
    )

    # positive control: a normal (non-reserved) tag key is accepted and persisted
    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"sim2real-behav-team": "kinesis"})
    tags_after = {
        t["Key"]: t["Value"]
        for t in kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    }
    assert tags_after.get("sim2real-behav-team") == "kinesis", (
        f"expected non-reserved tag to persist, got {tags_after!r}"
    )


def _client_error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
