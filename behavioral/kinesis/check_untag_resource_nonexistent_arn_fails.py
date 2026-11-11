"""untag-resource-nonexistent-arn-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _must_fail_code(fn):
    """Call fn(); return (code, message) of its error. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )

def _wait_stream_ready(c, name, timeout_s=150):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 90, 2, f"stream {name} shards addressable")

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, Tags={"sim2real-behav": "untag-resource-nonexistent-arn-fails"}, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _tags_for_arn(c, arn):
    return {t["Key"]: t["Value"] for t in c.list_tags_for_resource(ResourceARN=arn)["Tags"]}

def _stream_arn(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]

def _missing_stream_arn(ctx, c, live_stream_name):
    # Reuse the live ARN's account/region; a mismatched one fails auth before the lookup.
    real_arn = _stream_arn(c, live_stream_name)
    prefix = real_arn.rsplit("/", 1)[0]
    return f"{prefix}/{ctx.unique_name('sim2real-behav-kds-missing-')}"

CHECK = "untag-resource-nonexistent-arn-fails"
GROUP = 'tagging'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource on a nonexistent stream ARN fails with ResourceNotFoundException and its exact
    message, while the same call on a live stream's ARN removes the tag.
    """
    c = ctx.client("kinesis")
    live = _provisioned_stream(ctx, c, shard_count=1)
    live_arn = _stream_arn(c, live)

    # Positive control: without it, rejecting the missing ARN is indistinguishable from
    # rejecting every UntagResource call.
    c.tag_resource(ResourceARN=live_arn, Tags={"env": "sim2real-behav"})
    assert _tags_for_arn(c, live_arn).get("env") == "sim2real-behav", (
        "positive control: TagResource did not attach the tag"
    )
    c.untag_resource(ResourceARN=live_arn, TagKeys=["env"])
    assert "env" not in _tags_for_arn(c, live_arn), (
        "positive control: UntagResource on a live ARN did not remove the tag"
    )

    missing_arn = _missing_stream_arn(ctx, c, live)
    code, message = _must_fail_code(
        lambda: c.untag_resource(ResourceARN=missing_arn, TagKeys=["env"])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    missing_name = missing_arn.rsplit("/", 1)[1]
    expected_message = f"Stream {missing_name} under account {ctx.account} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected call against the missing ARN had no side effect on the live resource.
    assert "env" not in _tags_for_arn(c, live_arn), (
        "the rejected UntagResource on a missing ARN unexpectedly changed the live stream's tags"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
