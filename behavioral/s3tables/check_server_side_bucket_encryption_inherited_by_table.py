"""server-side-bucket-encryption-inherited-by-table."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "server-side-bucket-encryption-inherited-by-table"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table created under a bucket with server-side encryption configured
    inherits that encryption without an explicit table-level Put, verified via
    GetTableEncryption."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    s3tables.put_table_bucket_encryption(
        tableBucketARN=bucket_arn, encryptionConfiguration={"sseAlgorithm": "AES256"}
    )

    namespace_name = ctx.unique_name("ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace_name])
    ctx.on_cleanup(
        lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace_name)
    )
    table_name = ctx.unique_name("tbl_").replace("-", "_")
    s3tables.create_table(
        tableBucketARN=bucket_arn,
        namespace=namespace_name,
        name=table_name,
        format="ICEBERG",
        tags={"sim2real-behav": "s3tables"},
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(
            tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name
        )
    )

    table_enc = s3tables.get_table_encryption(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name
    )["encryptionConfiguration"]
    assert table_enc["sseAlgorithm"] == "AES256", (
        f"expected the table to inherit the bucket's AES256 default, got {table_enc}"
    )


def _create_table_bucket(ctx: Any) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-enc-inherit-")
    arn = s3tables.create_table_bucket(name=name, tags={"sim2real-behav": "s3tables"})["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
