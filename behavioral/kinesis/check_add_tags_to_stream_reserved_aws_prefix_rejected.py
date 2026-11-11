"""add-tags-to-stream-reserved-aws-prefix-rejected."""
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


def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(c, name)
    return name


def _tags_by_stream_name(c, name):
    return {t["Key"]: t["Value"] for t in c.list_tags_for_stream(StreamName=name)["Tags"]}


CHECK = "add-tags-to-stream-reserved-aws-prefix-rejected"
GROUP = "tagging"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddTagsToStream (keyed by StreamName) refuses a reserved 'aws:' tag key with the exact
    InvalidArgumentException, the rejected tag is not persisted in ListTagsForStream, and a
    non-reserved key through the same API succeeds and is visible."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)

    reserved_key = "aws:sim2real-behav"
    try:
        c.add_tags_to_stream(StreamName=name, Tags={reserved_key: "blocked"})
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"AddTagsToStream({reserved_key!r}) on stream {name} unexpectedly succeeded"
        )

    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException for a reserved 'aws:' tag key via "
        f"AddTagsToStream, got {code}"
    )
    expected_message = "Some tag keys in the request started with 'aws:'. System tags cannot be modified."
    assert message == expected_message, (
        f"AddTagsToStream({reserved_key!r}) answered {message!r}, expected {expected_message!r}"
    )

    tags_after = _tags_by_stream_name(c, name)
    assert reserved_key not in tags_after, (
        f"rejected {reserved_key!r} tag must not be persisted, saw {tags_after!r}"
    )

    c.add_tags_to_stream(StreamName=name, Tags={"sim2real-behav-allowed": "ok"})
    allowed = _poll(
        lambda: _tags_by_stream_name(c, name),
        lambda m: m.get("sim2real-behav-allowed") == "ok",
        timeout_s=30, interval_s=2,
        description="non-reserved tag visible via ListTagsForStream",
    )
    assert allowed.get("sim2real-behav-allowed") == "ok", (
        f"expected the non-reserved tag to be accepted and visible, got {allowed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
