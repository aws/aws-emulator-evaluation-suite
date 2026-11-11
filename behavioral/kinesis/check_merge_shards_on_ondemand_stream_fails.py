"""merge-shards-on-ondemand-stream-fails."""
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

def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

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

def _ondemand_stream(ctx, c):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _get_shards(c, name):
    return c.list_shards(StreamName=name)["Shards"]

CHECK = "merge-shards-on-ondemand-stream-fails"
GROUP = 'resharding'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MergeShards is not supported on ON_DEMAND streams and MUST fail, leaving the shard set
    unchanged."""
    c = ctx.client("kinesis")
    name = _ondemand_stream(ctx, c)
    shards = _get_shards(c, name)
    assert len(shards) >= 2, "expected on-demand stream to start with multiple shards"
    ids_before = sorted(s["ShardId"] for s in shards)

    error = _client_error(
        lambda: c.merge_shards(
            StreamName=name,
            ShardToMerge=shards[0]["ShardId"],
            AdjacentShardToMerge=shards[1]["ShardId"],
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException, got {error.get('Code')}"
    )
    expected_message = f"Request is invalid. Stream {name} under account {ctx.account} is in On-Demand mode."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    ids_after = sorted(s["ShardId"] for s in _get_shards(c, name))
    assert ids_after == ids_before, (
        f"rejected MergeShards must not change the shard set: before={ids_before}, after={ids_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
