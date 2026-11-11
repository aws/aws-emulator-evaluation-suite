"""put-table-bucket-storage-class-then-get-reflects-change."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-storage-class-then-get-reflects-change"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Setting a new storage class on a table bucket is durable and immediately
    observable via GetTableBucketStorageClass, regardless of whatever the bucket's
    initial default happened to be."""
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-sc-")
    arn = s3tables.create_table_bucket(
        name=name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-sc-"}
    )["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: s3tables.delete_table_bucket(tableBucketARN=arn)))

    initial = s3tables.get_table_bucket_storage_class(tableBucketARN=arn)
    initial_class = initial["storageClassConfiguration"]["storageClass"]
    target_class = "INTELLIGENT_TIERING" if initial_class != "INTELLIGENT_TIERING" else "STANDARD"

    s3tables.put_table_bucket_storage_class(
        tableBucketARN=arn, storageClassConfiguration={"storageClass": target_class}
    )

    updated_class = s3tables.get_table_bucket_storage_class(tableBucketARN=arn)[
        "storageClassConfiguration"
    ]["storageClass"]
    assert updated_class == target_class, f"expected {target_class!r}, got {updated_class!r}"
    assert updated_class != initial_class, (
        f"storage class did not change from initial value {initial_class!r}"
    )


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
