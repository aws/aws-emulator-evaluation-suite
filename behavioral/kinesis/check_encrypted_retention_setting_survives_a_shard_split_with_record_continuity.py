"""encrypted-retention-setting-survives-a-shard-split-with-record-continuity."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encrypted-retention-setting-survives-a-shard-split-with-record-continuity"
GROUP = "e2e"
SERVICES = ["kinesis"]


def _poll(probe, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _list_shards(kinesis, name, timeout_s=60.0, interval_s=2.0):
    """ListShards, retrying the transient ResourceInUseException a just-ACTIVE stream can still
    raise while its shard-map view catches up with its status view."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            err = exc.response["Error"]
            transient = err["Code"] == "ResourceInUseException" and (
                "CREATING" in err.get("Message", "") or "UPDATING" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _shard_iterator(kinesis, name, shard_id, timeout_s=60.0, interval_s=2.0):
    """GetShardIterator(TRIM_HORIZON), retrying the transient not-found a just-split child shard
    can still raise while its own view catches up with ListShards'."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.get_shard_iterator(
                StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
            )["ShardIterator"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _drain_all(kinesis, name, shard_id, timeout_s=60.0, interval_s=2.0, settle_reads=10):
    """Every record on ``shard_id`` from TRIM_HORIZON; returns once a closed shard is exhausted
    or an open one has read empty ``settle_reads`` times in a row."""
    iterator = _shard_iterator(kinesis, name, shard_id)
    collected = []
    deadline = time.monotonic() + timeout_s
    empty_reads = 0
    while True:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=1000)
        collected.extend(resp["Records"])
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected
        if not resp["Records"]:
            empty_reads += 1
            if empty_reads >= settle_reads:
                return collected
        else:
            empty_reads = 0
        iterator = nxt
        if time.monotonic() >= deadline:
            return collected
        time.sleep(interval_s)


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A stream's SSE-KMS encryption and an increased retention period both still describe as set
    after SplitShard creates two child shards, and the records put before the split -- both
    before and after enabling encryption -- read back from the closed parent as exact plaintext.

    Reference: https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html
    Reference: https://docs.aws.amazon.com/streams/latest/dev/kinesis-using-sdk-java-resharding.html
    """
    kinesis = ctx.client("kinesis")

    name = ctx.unique_name("sim2real-behav-kelc-")
    kinesis.create_stream(
        StreamName=name, ShardCount=1, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))

    def _summary():
        return kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]

    _poll(lambda: _summary()["StreamStatus"], lambda s: s == "ACTIVE", description="stream ACTIVE")
    initial = _summary()
    assert initial["RetentionPeriodHours"] == 24, (
        f"expected a freshly created stream to default to a 24h retention period, got "
        f"{initial['RetentionPeriodHours']!r}"
    )

    parent_shard = _list_shards(kinesis, name)[0]
    parent_shard_id = parent_shard["ShardId"]
    hash_range = parent_shard["HashKeyRange"]
    midpoint = str(
        (int(hash_range["StartingHashKey"]) + int(hash_range["EndingHashKey"])) // 2
    )

    put_before = kinesis.put_record(
        StreamName=name, Data=b"pre-encryption-record", PartitionKey="continuity-key"
    )
    assert put_before.get("EncryptionType") in (None, "NONE"), (
        f"expected no encryption before StartStreamEncryption, got "
        f"{put_before.get('EncryptionType')!r}"
    )

    kinesis.start_stream_encryption(StreamName=name, EncryptionType="KMS", KeyId="alias/aws/kinesis")
    _poll(
        lambda: _summary()["StreamStatus"], lambda s: s == "ACTIVE",
        description="stream ACTIVE after StartStreamEncryption",
    )
    assert _summary()["EncryptionType"] == "KMS", (
        f"expected EncryptionType=KMS after StartStreamEncryption, got "
        f"{_summary()['EncryptionType']!r}"
    )

    kinesis.increase_stream_retention_period(StreamName=name, RetentionPeriodHours=48)
    after_retention = _poll(
        _summary, lambda s: s["RetentionPeriodHours"] == 48,
        description="RetentionPeriodHours == 48 after IncreaseStreamRetentionPeriod",
    )
    assert after_retention["EncryptionType"] == "KMS", (
        f"increasing retention changed EncryptionType to {after_retention['EncryptionType']!r}"
    )

    # Each retry attempt is its own record with its own payload: per-shard encryption can still be
    # propagating when PutRecord returns, so a retry must not resend the same payload twice.
    after_payloads = []
    deadline = time.monotonic() + 180.0
    attempt = 0
    while True:
        attempt += 1
        payload = f"post-encryption-record-{attempt}".encode()
        put_after = kinesis.put_record(StreamName=name, Data=payload, PartitionKey="continuity-key")
        after_payloads.append(payload)
        if put_after.get("EncryptionType") == "KMS":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"PutRecord never reported EncryptionType=KMS within 180s across "
                f"{attempt} attempt(s); last {put_after!r}"
            )
        time.sleep(3)
    assert int(put_after["SequenceNumber"]) > int(put_before["SequenceNumber"]), (
        f"the post-encryption sequence number {put_after['SequenceNumber']} does not advance "
        f"past the pre-encryption one {put_before['SequenceNumber']}"
    )

    kinesis.split_shard(StreamName=name, ShardToSplit=parent_shard_id, NewStartingHashKey=midpoint)
    _poll(lambda: _summary()["StreamStatus"], lambda s: s == "ACTIVE", description="stream ACTIVE after SplitShard")

    def _children():
        return [
            s for s in _list_shards(kinesis, name)
            if s.get("ParentShardId") == parent_shard_id and "AdjacentParentShardId" not in s
        ]

    children = _poll(
        _children, lambda c: len(c) == 2,
        description=f"2 children of {parent_shard_id!r} visible in ListShards",
    )

    post_split = _summary()
    assert post_split["EncryptionType"] == "KMS", (
        f"SplitShard changed EncryptionType to {post_split['EncryptionType']!r}"
    )
    assert post_split["RetentionPeriodHours"] == 48, (
        f"SplitShard changed RetentionPeriodHours to {post_split['RetentionPeriodHours']!r}"
    )

    # Both records were put before SplitShard, so they live on the now-closed parent: a child's
    # TRIM_HORIZON iterator only replays records put after the split, never the parent's.
    found = [bytes(r["Data"]) for r in _drain_all(kinesis, name, parent_shard_id)]
    expected_parent = [b"pre-encryption-record"] + after_payloads
    assert found == expected_parent, (
        f"expected {expected_parent!r}, in put order, read back from the closed parent shard "
        f"{parent_shard_id!r} after SplitShard; got {found!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
