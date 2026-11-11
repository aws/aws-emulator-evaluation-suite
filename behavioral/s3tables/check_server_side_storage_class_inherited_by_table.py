"""server-side-storage-class-inherited-by-table."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "server-side-storage-class-inherited-by-table"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table created under a bucket with a configured (non-default) storage class
    inherits it by default, verified via GetTableStorageClass."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    s3tables.put_table_bucket_storage_class(
        tableBucketARN=bucket_arn,
        storageClassConfiguration={"storageClass": "INTELLIGENT_TIERING"},
    )
    bucket_sc = s3tables.get_table_bucket_storage_class(tableBucketARN=bucket_arn)[
        "storageClassConfiguration"
    ]["storageClass"]
    assert bucket_sc == "INTELLIGENT_TIERING", (
        f"bucket default storage class not applied: expected INTELLIGENT_TIERING, got {bucket_sc}"
    )

    namespace_name = ctx.unique_name("ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace_name])
    ctx.on_cleanup(
        lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name)
    )
    table_name = ctx.unique_name("tbl_").replace("-", "_")
    s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name, format="ICEBERG"
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(
            tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name
        )
    )

    table_sc = s3tables.get_table_storage_class(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name
    )["storageClassConfiguration"]["storageClass"]
    assert table_sc == "INTELLIGENT_TIERING", (
        f"table did not inherit bucket storage class: expected INTELLIGENT_TIERING, got {table_sc}"
    )


def _create_table_bucket(ctx: Any) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-sc-inherit-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
