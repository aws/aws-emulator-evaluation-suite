"""delete-table-bucket-encryption-then-get-reverts-to-aes256-default."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-table-bucket-encryption-then-get-reverts-to-aes256-default"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteTableBucketEncryption removes an explicit SSE-KMS configuration, GetTableBucketEncryption
    does not error but returns the default AES256 with no kmsKeyArn: S3 Tables always applies a default
    encryption to new tables."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    kms = ctx.client("kms")
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-s3t-key-"),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    s3t.put_table_bucket_encryption(
        tableBucketARN=bucket_arn,
        encryptionConfiguration={"sseAlgorithm": "aws:kms", "kmsKeyArn": key_arn},
    )

    # positive control: the KMS-backed configuration round-trips (bounded retry for
    # control-plane consistency, not an unconditional sleep)
    before_cfg = _poll_until(
        lambda: s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"],
        lambda cfg: cfg.get("sseAlgorithm") == "aws:kms",
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert before_cfg["sseAlgorithm"] == "aws:kms", (
        f"expected sseAlgorithm=aws:kms after PutTableBucketEncryption, got {before_cfg!r}"
    )
    assert before_cfg["kmsKeyArn"] == key_arn, (
        f"expected kmsKeyArn={key_arn!r} after PutTableBucketEncryption, got {before_cfg!r}"
    )

    s3t.delete_table_bucket_encryption(tableBucketARN=bucket_arn)

    # state-machine transition: the explicit override is gone and the bucket reverted
    # to the built-in default (AES256 / SSE-S3), not an error state
    after_cfg = _poll_until(
        lambda: s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"],
        lambda cfg: cfg.get("sseAlgorithm") != "aws:kms",
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert after_cfg["sseAlgorithm"] == "AES256", (
        f"expected reversion to sseAlgorithm=AES256 after DeleteTableBucketEncryption, got {after_cfg!r}"
    )
    assert "kmsKeyArn" not in after_cfg or not after_cfg["kmsKeyArn"], (
        f"expected no kmsKeyArn after reverting to the AES256 default, got {after_cfg!r}"
    )


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
