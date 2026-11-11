"""start-and-stop-stream-encryption."""
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
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

def _stream_description(c, name):
    return c.describe_stream(StreamName=name)["StreamDescription"]

def _encryption_type(c, name):
    return _stream_description(c, name)["EncryptionType"]

CHECK = "start-and-stop-stream-encryption"
GROUP = 'encryption'
SERVICES = ['kinesis']


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
    """Start/StopStreamEncryption toggle EncryptionType NONE <-> KMS: a resolved KeyId is present
    while encrypted and absent before encryption starts and after it stops."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    before = _stream_description(c, name)
    assert before["EncryptionType"] == "NONE", before
    assert not before.get("KeyId"), f"expected no KeyId before encryption is enabled, got {before.get('KeyId')!r}"

    kms = ctx.client("kms")
    key_id = kms.create_key(Description=name)["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    _start_encryption_with_new_key(ctx, c, name, key_id)
    _wait_stream_ready(c, name)
    encrypted = _poll(
        lambda: _stream_description(c, name),
        lambda d: d["EncryptionType"] == "KMS",
        timeout_s=120,
        interval_s=3,
        description="EncryptionType reaches KMS after StartStreamEncryption",
    )
    assert encrypted["KeyId"], "expected a resolved KMS KeyId once encryption is active"

    c.stop_stream_encryption(StreamName=name, EncryptionType="KMS", KeyId=encrypted["KeyId"])
    _wait_stream_ready(c, name)
    disabled = _poll(
        lambda: _stream_description(c, name),
        lambda d: d["EncryptionType"] == "NONE",
        timeout_s=120,
        interval_s=3,
        description="EncryptionType returns to NONE after StopStreamEncryption",
    )
    assert not disabled.get("KeyId"), f"expected no KeyId once disabled, got {disabled.get('KeyId')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
