"""put-and-get-table-bucket-storage-class."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-and-get-table-bucket-storage-class"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new table bucket's storage class is STANDARD and PutTableBucketStorageClass(INTELLIGENT_TIERING)
    is returned by GetTableBucketStorageClass; after the bucket is deleted, both the get and the put
    answer NotFoundException with "The specified bucket does not exist." as the message."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    before = s3t.get_table_bucket_storage_class(tableBucketARN=bucket_arn)
    got_before = before["storageClassConfiguration"]["storageClass"]
    assert got_before == "STANDARD", f"expected new bucket default STANDARD, got {got_before}"

    s3t.put_table_bucket_storage_class(
        tableBucketARN=bucket_arn,
        storageClassConfiguration={"storageClass": "INTELLIGENT_TIERING"},
    )

    after = s3t.get_table_bucket_storage_class(tableBucketARN=bucket_arn)
    got_after = after["storageClassConfiguration"]["storageClass"]
    assert got_after == "INTELLIGENT_TIERING", (
        f"expected INTELLIGENT_TIERING after put, got {got_after}"
    )

    s3t.delete_table_bucket(tableBucketARN=bucket_arn)

    read_code, read_message = _error(lambda: s3t.get_table_bucket_storage_class(tableBucketARN=bucket_arn))
    assert read_code == "NotFoundException", f"expected NotFoundException on read, got {read_code}"
    assert read_message == "The specified bucket does not exist.", (
        f"expected the exact not-found message on read, got {read_message!r}"
    )

    mutate_code, mutate_message = _error(
        lambda: s3t.put_table_bucket_storage_class(
            tableBucketARN=bucket_arn,
            storageClassConfiguration={"storageClass": "STANDARD"},
        )
    )
    assert mutate_code == "NotFoundException", (
        f"expected NotFoundException on mutation, got {mutate_code}"
    )
    assert mutate_message == "The specified bucket does not exist.", (
        f"expected the exact not-found message on mutation, got {mutate_message!r}"
    )


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name, tags={"sim2real:managed": "true"})["arn"]
    ctx.on_cleanup(lambda: _delete_quiet(s3t, arn))
    return arn


def _delete_quiet(s3t, arn) -> None:
    try:
        s3t.delete_table_bucket(tableBucketARN=arn)
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
