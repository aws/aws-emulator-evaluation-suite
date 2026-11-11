"""update-stream-mode-while-resharding-blocked."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-stream-mode-while-resharding-blocked"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStreamMode while the stream is UPDATING from a SplitShard fails ResourceInUseException
    and leaves the mode PROVISIONED; the same call succeeds once the stream is ACTIVE again."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-modeblock-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=2)
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))
    summary = _wait_stream_active(kinesis, stream_name)
    stream_arn = summary["StreamARN"]
    kinesis.add_tags_to_stream(
        StreamName=stream_name, Tags={"sim2real": "update-stream-mode-while-resharding-blocked"}
    )
    assert summary["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f"expected a freshly created stream to report PROVISIONED, got "
        f"{summary['StreamModeDetails']!r}"
    )

    shard = kinesis.list_shards(StreamARN=stream_arn)["Shards"][0]
    start = int(shard["HashKeyRange"]["StartingHashKey"])
    end = int(shard["HashKeyRange"]["EndingHashKey"])
    midpoint = start + (end - start) // 2
    assert start < midpoint <= end, (
        f"expected a splittable midpoint strictly between the shard's hash-key bounds "
        f"[{start}, {end}], computed {midpoint}"
    )

    kinesis.split_shard(
        StreamARN=stream_arn, ShardToSplit=shard["ShardId"], NewStartingHashKey=str(midpoint)
    )

    # Fired immediately so the SplitShard reshard is still in flight (stream UPDATING).
    code, message = _error_code(
        lambda: kinesis.update_stream_mode(
            StreamARN=stream_arn, StreamModeDetails={"StreamMode": "ON_DEMAND"}
        )
    )
    assert code == "ResourceInUseException", (
        f"expected UpdateStreamMode to be rejected with ResourceInUseException while the "
        f"SplitShard reshard is still in flight, got {code!r}"
    )
    expected_message = (
        f"Stream {stream_name} under account {ctx.account} not ACTIVE, instead in state UPDATING"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    mid_summary = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"]
    assert mid_summary["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f"the rejected UpdateStreamMode must have no effect: expected capacity mode to remain "
        f"PROVISIONED, got {mid_summary['StreamModeDetails']!r}"
    )

    _wait_stream_active(kinesis, stream_name)

    # Positive control: the rejection was specific to the in-flight reshard.
    kinesis.update_stream_mode(
        StreamARN=stream_arn, StreamModeDetails={"StreamMode": "ON_DEMAND"}
    )
    final_summary = _wait_stream_active(kinesis, stream_name)
    assert final_summary["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f"expected the identical UpdateStreamMode call to succeed once the stream settled back "
        f"to ACTIVE, got {final_summary['StreamModeDetails']!r}"
    )


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE, last={summary}")


def _error_code(fn) -> tuple[str, str]:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            raise
        err = response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _safe_delete_stream(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
