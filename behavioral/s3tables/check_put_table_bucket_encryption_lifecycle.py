"""put-table-bucket-encryption-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-table-bucket-encryption-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableBucketEncryption returns AES256 after a put; after DeleteTableBucketEncryption it returns
    the AES256 default with no kmsKeyArn instead of an error, and a second delete answers
    NotFoundException with 'The specified encryption configuration does not exist.'"""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    s3t.put_table_bucket_encryption(
        tableBucketARN=bucket_arn,
        encryptionConfiguration={"sseAlgorithm": "AES256"},
    )
    got = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert got["sseAlgorithm"] == "AES256", f"expected AES256 after put, got {got}"

    s3t.delete_table_bucket_encryption(tableBucketARN=bucket_arn)

    after = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert after["sseAlgorithm"] == "AES256", (
        f"expected revert to the AES256 default after delete, got {after}"
    )
    assert not after.get("kmsKeyArn"), f"expected no kmsKeyArn after revert, got {after}"

    # the explicit override is actually gone, not silently retained: deleting again
    # (nothing explicit left to delete) fails with the specific not-found code.
    code, message = _error(lambda: s3t.delete_table_bucket_encryption(tableBucketARN=bucket_arn))
    assert code == "NotFoundException", f"expected NotFoundException on double-delete, got {code!r}"
    assert message == "The specified encryption configuration does not exist.", (
        f"expected the exact not-found message on double-delete, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
