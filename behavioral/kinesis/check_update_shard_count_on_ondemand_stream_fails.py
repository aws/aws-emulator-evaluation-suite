"""update-shard-count-on-ondemand-stream-fails."""
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

def _error_code(fn):
    """Call fn(); return its Error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected UpdateShardCount to be rejected on an ON_DEMAND stream, but it SUCCEEDED "
        f"and returned {result!r}"
    )

def _create_stream_with_retry(c, name, tags_dict, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, Tags=tags_dict, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    return _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda summary: summary["StreamStatus"] == "ACTIVE",
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
    name = ctx.unique_name("sim2real-behav-kds-prov-")
    _create_stream_with_retry(c, name, {"sim2real-check": CHECK}, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _ondemand_stream(ctx, c):
    name = ctx.unique_name("sim2real-behav-kds-ondemand-")
    _create_stream_with_retry(c, name, {"sim2real-check": CHECK}, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

CHECK = "update-shard-count-on-ondemand-stream-fails"
GROUP = 'resharding'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateShardCount is only valid for PROVISIONED streams and MUST fail on ON_DEMAND, with
    no effect on the stream's shards."""
    c = ctx.client("kinesis")

    # Positive control: the identical operation succeeds on a PROVISIONED stream, so the
    # rejection below is specific to ON_DEMAND rather than a sign the account/credentials
    # cannot exercise UpdateShardCount at all.
    prov_name = _provisioned_stream(ctx, c, shard_count=1)
    resp = c.update_shard_count(StreamName=prov_name, TargetShardCount=2, ScalingType="UNIFORM_SCALING")
    assert resp["CurrentShardCount"] == 1, f"expected CurrentShardCount 1, got {resp['CurrentShardCount']}"
    assert resp["TargetShardCount"] == 2, f"expected TargetShardCount 2, got {resp['TargetShardCount']}"
    _wait_stream_ready(c, prov_name)

    ondemand_name = _ondemand_stream(ctx, c)
    before = c.describe_stream_summary(StreamName=ondemand_name)["StreamDescriptionSummary"]
    assert before["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f"expected fixture stream to be ON_DEMAND, got {before['StreamModeDetails']}"
    )
    before_shard_count = before["OpenShardCount"]

    code, message = _error_code(
        lambda: c.update_shard_count(
            StreamName=ondemand_name, TargetShardCount=2, ScalingType="UNIFORM_SCALING"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        f"Request is invalid. Stream {ondemand_name} under account {ctx.account} is in On-Demand mode."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Independent read at the destination: the rejected call left no trace on the stream.
    after = c.describe_stream_summary(StreamName=ondemand_name)["StreamDescriptionSummary"]
    assert after["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f"expected stream to remain ON_DEMAND after the rejected call, got {after['StreamModeDetails']}"
    )
    assert after["OpenShardCount"] == before_shard_count, (
        f"expected open shard count to stay {before_shard_count} after the rejected call, "
        f"got {after['OpenShardCount']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
