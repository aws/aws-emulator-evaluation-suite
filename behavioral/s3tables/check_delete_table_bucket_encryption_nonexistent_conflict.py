"""delete-table-bucket-encryption-nonexistent-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-table-bucket-encryption-nonexistent-conflict"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTableBucketEncryption on a bucket that only has the implicit AES256 default is NotFoundException
    "The specified encryption configuration does not exist." and leaves that default unchanged, while
    deleting an explicitly put configuration succeeds and the bucket reads AES256."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_bucket(ctx, "delenc")

    # Baseline: a fresh bucket always reports an (implicit default) encryption config.
    baseline = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert baseline["sseAlgorithm"] == "AES256", f"expected implicit default AES256, got {baseline}"

    # Deleting encryption that was never explicitly configured is rejected.
    code, message = _error(lambda: s3t.delete_table_bucket_encryption(tableBucketARN=bucket_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "The specified encryption configuration does not exist.", message

    # Effect absent: the default encryption is untouched by the failed delete.
    after = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert after == baseline, f"default encryption changed after rejected delete: {baseline} -> {after}"

    # Positive control: once encryption is explicitly put, deleting it succeeds.
    s3t.put_table_bucket_encryption(
        tableBucketARN=bucket_arn, encryptionConfiguration={"sseAlgorithm": "AES256"}
    )
    s3t.delete_table_bucket_encryption(tableBucketARN=bucket_arn)
    reverted = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert reverted["sseAlgorithm"] == "AES256", f"expected revert to AES256, got {reverted}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, suffix: str) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
