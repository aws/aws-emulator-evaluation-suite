"""put-table-bucket-encryption-then-delete-then-get-reverts-to-default."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-encryption-then-delete-then-get-reverts-to-default"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After an SSE-KMS config round-trips, DeleteTableBucketEncryption makes GetTableBucketEncryption
    report the AES256 default, neither serving the removed KMS config nor returning NotFound."""
    s3tables = ctx.client("s3tables")
    kms = ctx.client("kms")

    name = ctx.unique_name("sim2real-s3t-enc-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: s3tables.delete_table_bucket(tableBucketARN=arn)))

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-s3t-enc-key-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        )
    )

    s3tables.put_table_bucket_encryption(
        tableBucketARN=arn,
        encryptionConfiguration={"sseAlgorithm": "aws:kms", "kmsKeyArn": key_arn},
    )

    # Positive control: the SSE-KMS configuration we just wrote round-trips immediately.
    got = _poll_until(
        lambda: s3tables.get_table_bucket_encryption(tableBucketARN=arn)["encryptionConfiguration"],
        lambda cfg: cfg.get("sseAlgorithm") == "aws:kms",
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert got["sseAlgorithm"] == "aws:kms", f"expected aws:kms after put, got {got['sseAlgorithm']!r}"
    assert got["kmsKeyArn"] == key_arn, f"expected kmsKeyArn={key_arn!r}, got {got.get('kmsKeyArn')!r}"

    s3tables.delete_table_bucket_encryption(tableBucketARN=arn)

    # After delete, the bucket must revert to the SSE-S3/AES256 default -- not keep
    # serving the KMS config we just removed, and not 404.
    reverted = _poll_until(
        lambda: s3tables.get_table_bucket_encryption(tableBucketARN=arn)["encryptionConfiguration"],
        lambda cfg: cfg.get("sseAlgorithm") != "aws:kms",
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert reverted["sseAlgorithm"] == "AES256", (
        f"expected reversion to AES256 default after delete, got {reverted['sseAlgorithm']!r}"
    )
    assert "kmsKeyArn" not in reverted, f"expected no kmsKeyArn after revert, found {reverted.get('kmsKeyArn')!r}"


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
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
