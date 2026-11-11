"""get-shard-iterator-nonexistent-stream-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=90, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _client_error(fn):
    """Call fn(); return its (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


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


def _provisioned_stream(ctx, c):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=1)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        description=f"stream {name} ACTIVE",
    )
    return name


CHECK = "get-shard-iterator-nonexistent-stream-fails"
GROUP = 'error-semantics'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetShardIterator on a never-created stream fails with ResourceNotFoundException and its exact
    message, while the same call on a real stream succeeds (positive control)."""
    c = ctx.client("kinesis")

    real_name = _provisioned_stream(ctx, c)
    shard_id = c.list_shards(StreamName=real_name)["Shards"][0]["ShardId"]
    resp = c.get_shard_iterator(
        StreamName=real_name, ShardId=shard_id, ShardIteratorType="LATEST"
    )
    assert resp.get("ShardIterator"), "positive control: GetShardIterator returned no iterator for a real stream"

    missing_name = ctx.unique_name("sim2real-behav-kds-missing-")
    code, message = _client_error(
        lambda: c.get_shard_iterator(
            StreamName=missing_name, ShardId="shardId-000000000000", ShardIteratorType="LATEST"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = (
        f"Shard shardId-000000000000 in stream {missing_name} under account {ctx.account} does not exist"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
