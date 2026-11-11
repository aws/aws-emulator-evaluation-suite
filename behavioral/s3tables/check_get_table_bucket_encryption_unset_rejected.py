"""get-table-bucket-encryption-unset-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-table-bucket-encryption-unset-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableBucketEncryption returns the implicit AES256 default on a bucket that never had encryption
    put, and after the bucket is deleted answers NotFoundException "The specified bucket does not
    exist." instead of a stale or default configuration."""
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-encget-")
    bucket_arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_tolerating_absent(s3t, bucket_arn))

    # positive control: while the bucket exists, GetTableBucketEncryption succeeds --
    # even with no explicit PutTableBucketEncryption call -- via the implicit default
    got = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    assert got["encryptionConfiguration"]["sseAlgorithm"] == "AES256", (
        f"expected implicit default AES256 before delete, got {got['encryptionConfiguration']!r}"
    )

    s3t.delete_table_bucket(tableBucketARN=bucket_arn)

    code, message = _error(lambda: s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "The specified bucket does not exist.", (
        f"expected the exact not-found message for the deleted bucket, got {message!r}"
    )


def _delete_bucket_tolerating_absent(s3t, bucket_arn: str) -> None:
    try:
        s3t.delete_table_bucket(tableBucketARN=bucket_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
