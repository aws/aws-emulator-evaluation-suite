"""auto-accepts-missing-partition-key-user-mode-rejects-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auto-accepts-missing-partition-key-user-mode-rejects-it"
GROUP = "validation"
SERVICES = ["kinesis"]

_NULL_PARTITION_KEY = (
    "ValidationException",
    "1 validation error detected: Value null at 'partitionKey' failed to satisfy "
    "constraint: Member must not be null",
)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord/PutRecords with no PartitionKey succeed while AUTO distributes records; the
    same calls fail with ValidationException once the stream switches back to USER_PARTITION_KEY,
    and no record from a failed call is ever appended."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinpk-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(ctx, name))
    summary = _wait_stream_status(ctx, name, {"ACTIVE"}, timeout_s=180)
    stream_arn = summary["StreamARN"]

    kinesis.update_stream_record_distribution_strategy(
        StreamARN=stream_arn, RecordDistributionStrategy="AUTO"
    )
    _wait_strategy(ctx, name, "AUTO")

    # A keyless PutRecord is refused with the exact null-partitionKey pair until the switch
    # takes effect; a refused put appends nothing, so it is retried.
    _until_accepted(lambda: kinesis.put_record(StreamName=name, Data=b"auto-no-pk"))

    puts_resp = kinesis.put_records(
        StreamName=name, Records=[{"Data": b"auto-no-pk-1"}, {"Data": b"auto-no-pk-2"}]
    )
    assert puts_resp["FailedRecordCount"] == 0, (
        f"PutRecords with no PartitionKey under AUTO must succeed for every entry, "
        f"FailedRecordCount={puts_resp['FailedRecordCount']}, records={puts_resp['Records']!r}"
    )

    kinesis.update_stream_record_distribution_strategy(
        StreamARN=stream_arn, RecordDistributionStrategy="USER_PARTITION_KEY"
    )
    _wait_strategy(ctx, name, "USER_PARTITION_KEY")
    # Probes with distinct data run until the switch takes effect; any accepted before then is
    # expected on the stream.
    accepted_probes = _until_refused(kinesis, name)

    code, message = _refusal(lambda: kinesis.put_record(StreamName=name, Data=b"user-no-pk"))
    assert (code, message) == _NULL_PARTITION_KEY, f"keyless PutRecord gave {code!r} {message!r}"

    code, message = _refusal(
        lambda: kinesis.put_records(
            StreamName=name, Records=[{"Data": b"user-no-pk-1"}, {"Data": b"user-no-pk-2"}]
        )
    )
    expected_batch = (
        "ValidationException",
        "2 validation errors detected: "
        "Value null at 'records.1.member.partitionKey' failed to satisfy constraint: "
        "Member must not be null; "
        "Value null at 'records.2.member.partitionKey' failed to satisfy constraint: "
        "Member must not be null",
    )
    assert (code, message) == expected_batch, f"keyless PutRecords gave {code!r} {message!r}"

    all_data = _read_all_records(kinesis, stream_arn)
    expected_data = {b"auto-no-pk", b"auto-no-pk-1", b"auto-no-pk-2"} | accepted_probes
    assert all_data == expected_data, (
        f"only the records accepted under AUTO should ever land on the stream; "
        f"found {all_data!r}, expected {expected_data!r} (nothing from the refused calls)"
    )


def _wait_strategy(ctx, name: str, strategy: str, timeout_s: float = 120.0) -> None:
    """Poll DescribeStreamSummary until the stream is ACTIVE and reports ``strategy``."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE" and summary.get("RecordDistributionStrategy") == strategy:
            return
        time.sleep(3)
    raise AssertionError(f"stream {name} never reported ACTIVE with {strategy} in {timeout_s}s (last={summary})")


def _until_accepted(fn, timeout_s: float = 120.0):
    """fn()'s result, retrying only the exact null-partitionKey refusal."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"], err.get("Message")) != _NULL_PARTITION_KEY or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _until_refused(kinesis, name: str, timeout_s: float = 120.0) -> set:
    """Keyless probe puts, each with distinct data, until one is refused with the exact
    null-partitionKey pair; the data of every accepted probe."""
    accepted: set = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        data = f"user-probe-{len(accepted)}".encode()
        try:
            kinesis.put_record(StreamName=name, Data=data)
        except ClientError as exc:
            err = exc.response["Error"]
            assert (err["Code"], err.get("Message")) == _NULL_PARTITION_KEY, (
                f"keyless probe PutRecord gave {err['Code']!r} {err.get('Message')!r}"
            )
            return accepted
        accepted.add(data)
        time.sleep(2)
    raise AssertionError(f"keyless PutRecord was still accepted {timeout_s}s after USER_PARTITION_KEY")


def _refusal(fn):
    """(code, message) of a call that MUST be refused. A success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _delete_stream_ignore_missing(ctx, name: str) -> None:
    try:
        ctx.client("kinesis").delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_stream_status(ctx, name: str, target_statuses, timeout_s: float = 180.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] in target_statuses:
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {name} did not reach {target_statuses} in {timeout_s}s (last={summary})")


def _read_all_records(kinesis, stream_arn: str) -> set:
    """Every record's Data read from every open and closed shard, from TRIM_HORIZON."""
    found: set = set()
    kwargs = {"StreamARN": stream_arn}
    shard_ids = []
    while True:
        page = kinesis.list_shards(**kwargs)
        shard_ids.extend(shard["ShardId"] for shard in page["Shards"])
        next_token = page.get("NextToken")
        if not next_token:
            break
        kwargs = {"StreamARN": stream_arn, "NextToken": next_token}

    for shard_id in shard_ids:
        iterator = kinesis.get_shard_iterator(
            StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        for _ in range(20):
            page = kinesis.get_records(StreamARN=stream_arn, ShardIterator=iterator, Limit=1000)
            for record in page["Records"]:
                found.add(record["Data"])
            iterator = page.get("NextShardIterator")
            if not iterator or (not page["Records"] and page.get("MillisBehindLatest") == 0):
                break
            time.sleep(0.25)
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
