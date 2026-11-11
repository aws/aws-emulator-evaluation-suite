"""update-stream-mode-switches-provisioned-to-ondemand."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stream-mode-switches-provisioned-to-ondemand"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStreamMode switches a stream from PROVISIONED to ON_DEMAND and DescribeStreamSummary
    reflects it; its OpenShardCount must agree with the open shards ListShards returns."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinstrm-")
    kinesis.create_stream(
        StreamName=name, ShardCount=1, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(ctx, name))
    _wait_stream_status(ctx, name, {"ACTIVE"}, timeout_s=180)

    summary_before = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert summary_before["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f"expected PROVISIONED right after create_stream, got {summary_before['StreamModeDetails']}"
    )
    shard_count_before = summary_before["OpenShardCount"]
    assert shard_count_before == 1, f"expected 1 open shard from ShardCount=1, got {shard_count_before}"
    stream_arn = summary_before["StreamARN"]

    kinesis.update_stream_mode(StreamARN=stream_arn, StreamModeDetails={"StreamMode": "ON_DEMAND"})

    summary_after = _wait_stream_mode(ctx, name, "ON_DEMAND", timeout_s=180)
    assert summary_after["StreamStatus"] == "ACTIVE", (
        f"expected ACTIVE after the mode switch settled, got {summary_after['StreamStatus']}"
    )
    assert summary_after["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f"expected ON_DEMAND after UpdateStreamMode, got {summary_after['StreamModeDetails']}"
    )

    # AWS need not reshard on the switch, so assert consistency rather than shard growth.
    open_shard_count = _count_open_shards(kinesis, stream_arn)
    assert open_shard_count == summary_after["OpenShardCount"], (
        f"ListShards reports {open_shard_count} open shard(s) but DescribeStreamSummary "
        f"reports OpenShardCount={summary_after['OpenShardCount']} for the same ON_DEMAND stream"
    )


def _count_open_shards(kinesis, stream_arn: str) -> int:
    open_count = 0
    kwargs = {"StreamARN": stream_arn}
    while True:
        page = kinesis.list_shards(**kwargs)
        for shard in page["Shards"]:
            if "EndingSequenceNumber" not in shard["SequenceNumberRange"]:
                open_count += 1
        next_token = page.get("NextToken")
        if not next_token:
            return open_count
        kwargs = {"NextToken": next_token}


def _delete_stream_ignore_missing(ctx, name: str) -> None:
    try:
        ctx.client("kinesis").delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_status(ctx, name: str, target_statuses, timeout_s: float = 180.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"stream {name} did not reach {target_statuses} in {timeout_s}s (last={status})")


def _wait_stream_mode(ctx, name: str, target_mode: str, timeout_s: float = 180.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE" and summary["StreamModeDetails"]["StreamMode"] == target_mode:
            return summary
        time.sleep(3)
    raise AssertionError(
        f"stream {name} did not converge to ACTIVE/{target_mode} in {timeout_s}s (last={summary})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
