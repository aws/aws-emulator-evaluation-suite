"""table-inherits-bucket-storage-class."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "table-inherits-bucket-storage-class"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After the bucket's storage class is set to INTELLIGENT_TIERING, a table created without a
    storageClassConfiguration reports INTELLIGENT_TIERING from GetTableStorageClass: a table inherits
    its bucket's storage class."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    s3t.put_table_bucket_storage_class(
        tableBucketARN=bucket_arn,
        storageClassConfiguration={"storageClass": "INTELLIGENT_TIERING"},
    )
    bucket_sc = s3t.get_table_bucket_storage_class(tableBucketARN=bucket_arn)[
        "storageClassConfiguration"
    ]["storageClass"]
    assert bucket_sc == "INTELLIGENT_TIERING", (
        f"bucket default storage class not applied: expected INTELLIGENT_TIERING, got {bucket_sc}"
    )

    _create_namespace(ctx, bucket_arn, "ns")
    s3t.create_table(tableBucketARN=bucket_arn, namespace="ns", name="tbl", format="ICEBERG")
    ctx.on_cleanup(
        lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace="ns", name="tbl")
    )

    table_sc = s3t.get_table_storage_class(
        tableBucketARN=bucket_arn, namespace="ns", name="tbl"
    )["storageClassConfiguration"]["storageClass"]
    assert table_sc == "INTELLIGENT_TIERING", (
        f"table did not inherit bucket storage class: expected INTELLIGENT_TIERING, got {table_sc}"
    )


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn: str, ns: str) -> None:
    s3t = ctx.client("s3tables")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=ns))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
