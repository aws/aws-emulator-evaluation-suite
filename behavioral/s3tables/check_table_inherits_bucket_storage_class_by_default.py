"""table-inherits-bucket-storage-class-by-default."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "table-inherits-bucket-storage-class-by-default"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table created in a bucket with a configured storage class inherits it without a table-level put."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    s3tables.put_table_bucket_storage_class(
        tableBucketARN=bucket_arn,
        storageClassConfiguration={"storageClass": "INTELLIGENT_TIERING"},
    )
    bucket_class = s3tables.get_table_bucket_storage_class(tableBucketARN=bucket_arn)
    assert bucket_class["storageClassConfiguration"]["storageClass"] == "INTELLIGENT_TIERING", (
        f"expected the bucket-level put to take effect (INTELLIGENT_TIERING), got {bucket_class}"
    )

    namespace = _underscored(ctx.unique_name("ns"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace))

    table_name = _underscored(ctx.unique_name("tbl"))
    # Deliberately no storageClassConfiguration on the table itself.
    s3tables.create_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name, format="ICEBERG")
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    )

    table_class = s3tables.get_table_storage_class(
        tableBucketARN=bucket_arn, namespace=namespace, name=table_name
    )
    assert table_class["storageClassConfiguration"]["storageClass"] == "INTELLIGENT_TIERING", (
        f"table created with no explicit storageClassConfiguration should inherit the "
        f"bucket's INTELLIGENT_TIERING default, got {table_class}"
    )


def _underscored(name: str) -> str:
    return name.replace("-", "_").lower()


def _create_table_bucket(ctx, s3tables):
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-sc-inherit"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
