"""delete-table-bucket-encryption-without-config-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-bucket-encryption-without-config-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTableBucketEncryption on a bucket with only the implicit AES256 default is NotFoundException
    "The specified encryption configuration does not exist." and changes nothing, while after an
    explicit aws:kms put the delete succeeds and the bucket reads AES256 with no kmsKeyArn."""
    s3tables = ctx.client("s3tables")
    kms = ctx.client("kms")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    before = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)[
        "encryptionConfiguration"
    ]
    assert before["sseAlgorithm"] == "AES256", f"expected implicit default AES256, got {before}"

    code, message = _error(
        lambda: s3tables.delete_table_bucket_encryption(tableBucketARN=bucket_arn)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "The specified encryption configuration does not exist.", message

    after = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)[
        "encryptionConfiguration"
    ]
    assert after == before, f"default encryption changed after rejected delete: {before} -> {after}"

    # Positive control: once encryption has been EXPLICITLY configured (SSE-KMS,
    # deliberately distinct from the AES256 implicit default) deleting it succeeds
    # and reverts the bucket to the AES256 default -- a real revert is now
    # distinguishable from a no-op delete that just left the KMS config in place.
    key_arn = kms.create_key(Description=ctx.unique_name("sim2real-s3t-key-"))[
        "KeyMetadata"
    ]["Arn"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(
            KeyId=key_arn, PendingWindowInDays=7
        )
    )
    s3tables.put_table_bucket_encryption(
        tableBucketARN=bucket_arn,
        encryptionConfiguration={"sseAlgorithm": "aws:kms", "kmsKeyArn": key_arn},
    )
    configured = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)[
        "encryptionConfiguration"
    ]
    assert configured["sseAlgorithm"] == "aws:kms", f"explicit KMS config did not take: {configured}"
    assert configured["kmsKeyArn"] == key_arn, f"kmsKeyArn drifted: {configured}"

    s3tables.delete_table_bucket_encryption(tableBucketARN=bucket_arn)
    restored = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)[
        "encryptionConfiguration"
    ]
    assert restored["sseAlgorithm"] == "AES256", f"expected revert to AES256 default, got {restored}"
    assert "kmsKeyArn" not in restored or not restored["kmsKeyArn"], (
        f"kmsKeyArn survived the delete, delete did not actually revert: {restored}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
