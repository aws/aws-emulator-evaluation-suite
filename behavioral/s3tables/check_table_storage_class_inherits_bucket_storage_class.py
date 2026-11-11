"""table-storage-class-inherits-bucket-storage-class."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "table-storage-class-inherits-bucket-storage-class"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table created without a storage class under an INTELLIGENT_TIERING bucket reports
    INTELLIGENT_TIERING from GetTableStorageClass, while a sibling created with an explicit STANDARD
    class reports STANDARD: the get returns the table's own configuration."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    s3t.put_table_bucket_storage_class(
        tableBucketARN=bucket_arn,
        storageClassConfiguration={"storageClass": "INTELLIGENT_TIERING"},
    )

    namespace = _create_namespace(ctx, bucket_arn)
    _inherited_arn, inherited_name = _create_table(ctx, bucket_arn, namespace)

    inherited = s3t.get_table_storage_class(
        tableBucketARN=bucket_arn, namespace=namespace, name=inherited_name
    )["storageClassConfiguration"]["storageClass"]
    assert inherited == "INTELLIGENT_TIERING", (
        "table created with no table-level storageClassConfiguration must inherit the "
        f"bucket default INTELLIGENT_TIERING; GetTableStorageClass reported {inherited!r}"
    )

    _overridden_arn, overridden_name = _create_table(
        ctx, bucket_arn, namespace, storage_class="STANDARD"
    )
    overridden = s3t.get_table_storage_class(
        tableBucketARN=bucket_arn, namespace=namespace, name=overridden_name
    )["storageClassConfiguration"]["storageClass"]
    assert overridden == "STANDARD", (
        "table created WITH an explicit table-level storageClassConfiguration=STANDARD "
        f"must keep it, not the bucket default; GetTableStorageClass reported {overridden!r}"
    )


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn):
    s3t = ctx.client("s3tables")
    namespace = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace))
    return namespace


def _create_table(ctx, bucket_arn, namespace, storage_class=None):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    kwargs = {}
    if storage_class is not None:
        kwargs["storageClassConfiguration"] = {"storageClass": storage_class}
    resp = s3t.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG", **kwargs
    )
    ctx.on_cleanup(
        lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    )
    return resp["tableARN"], name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
