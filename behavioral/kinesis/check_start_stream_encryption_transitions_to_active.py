"""start-stream-encryption-transitions-to-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-stream-encryption-transitions-to-active"
GROUP = "state-machine"
SERVICES = ["kinesis"]


def _start_encryption_with_new_key(ctx, client, stream_name, key_id):
    """StartStreamEncryption with a key created moments before; Kinesis may not resolve a new
    key for a few seconds, so KMSNotFoundException is retried for up to 60 s, within the budget."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(0.0, min(60.0, left - 10.0)))
    while True:
        try:
            return client.start_stream_encryption(
                StreamName=stream_name, EncryptionType="KMS", KeyId=key_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMSNotFoundException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartStreamEncryption moves the stream through UPDATING back to ACTIVE with
    encryption enabled, and the data plane keeps working once encrypted."""
    kinesis = ctx.client("kinesis")
    stream = _create_provisioned_stream(ctx)

    before = kinesis.describe_stream(StreamName=stream["name"])["StreamDescription"]
    assert before["EncryptionType"] == "NONE", (
        f"a freshly created stream must report EncryptionType=NONE, got {before['EncryptionType']!r}"
    )

    kms = ctx.client("kms")
    key_id = kms.create_key(Description=stream["name"])["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    # The check's own alias: Kinesis echoes the KeyId it was given verbatim, alias name included.
    alias = f"alias/{ctx.unique_name('sim2real-kinesis-')}"
    kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=alias))
    _start_encryption_with_new_key(ctx, kinesis, stream["name"], alias)

    # The poll's own predicate already establishes StreamStatus == ACTIVE and
    # EncryptionType == KMS on `desc` by construction, so re-asserting either here would be a
    # tautology that cannot fail. KeyId is not part of that predicate, so it is the one field
    # here that still carries information.
    desc = _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream["name"])["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE" and d["EncryptionType"] == "KMS",
        timeout_s=180,
        interval_s=3,
    )
    assert desc["KeyId"] == alias, (
        f"expected StartStreamEncryption's KeyId echoed back verbatim, got {desc.get('KeyId')!r}"
    )

    # Confirm the data plane still round-trips correctly once encryption is active, and that the
    # record itself is labelled as encrypted (not just the stream description).
    put = kinesis.put_record(StreamName=stream["name"], Data=b"post-encryption-payload", PartitionKey="pk-1")
    shard_id = put["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamName=stream["name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records = _poll_until(
        lambda: kinesis.get_records(ShardIterator=iterator, Limit=10),
        lambda r: len(r.get("Records", [])) >= 1,
        timeout_s=60,
        interval_s=2,
    )
    payloads = [r["Data"] for r in records["Records"]]
    assert payloads == [b"post-encryption-payload"], (
        f"GetRecords after enabling encryption returned {payloads!r}; expected exactly the "
        f"just-put payload"
    )
    assert records["Records"][0].get("EncryptionType") == "KMS", (
        f"the record itself reports EncryptionType={records['Records'][0].get('EncryptionType')!r}, "
        f"expected KMS"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_provisioned_stream(ctx, shard_count=1):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kenc-")
    kinesis.create_stream(
        StreamName=name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"}
    )

    def _cleanup():
        try:
            kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
