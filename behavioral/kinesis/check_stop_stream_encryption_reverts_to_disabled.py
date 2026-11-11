"""stop-stream-encryption-reverts-to-disabled."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-stream-encryption-reverts-to-disabled"
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopStreamEncryption transitions encryption status back to NONE once the
    stream returns to ACTIVE."""
    kinesis = ctx.client("kinesis")
    stream = _create_provisioned_stream(ctx)

    kms = ctx.client("kms")
    key_id = kms.create_key(Description=stream["name"])["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    _start_encryption_with_new_key(ctx, kinesis, stream["name"], key_id)
    active_encrypted = _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream["name"])["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE" and d["EncryptionType"] == "KMS",
        timeout_s=180,
        interval_s=3,
    )
    resolved_key_id = active_encrypted["KeyId"]

    kinesis.stop_stream_encryption(
        StreamName=stream["name"], EncryptionType="KMS", KeyId=resolved_key_id
    )
    disabled = _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream["name"])["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE" and d["EncryptionType"] == "NONE",
        timeout_s=180,
        interval_s=3,
    )
    summary = kinesis.describe_stream_summary(StreamName=stream["name"])["StreamDescriptionSummary"]
    assert summary["EncryptionType"] == "NONE", (
        f"describe_stream_summary still reports EncryptionType={summary['EncryptionType']!r} "
        f"after describe_stream settled to NONE post-StopStreamEncryption"
    )
    assert disabled.get("KeyId") in (None, ""), f"expected no KeyId once disabled, got {disabled.get('KeyId')!r}"


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
    kinesis.create_stream(StreamName=name, ShardCount=shard_count, Tags={"sim2real": "ga-depth-kinesis"})

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
