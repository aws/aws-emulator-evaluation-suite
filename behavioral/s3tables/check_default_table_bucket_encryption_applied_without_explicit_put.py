"""default-table-bucket-encryption-applied-without-explicit-put."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "default-table-bucket-encryption-applied-without-explicit-put"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created table bucket already has server-managed SSE-S3 default encryption active."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    # No PutTableBucketEncryption call has been made -- the default must already be in effect.
    resp = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    enc = resp["encryptionConfiguration"]
    assert enc["sseAlgorithm"] == "AES256", f"expected default SSE-S3 (AES256), got {enc}"
    assert not enc.get("kmsKeyArn"), f"expected no kmsKeyArn on the default, got {enc}"


def _create_table_bucket(ctx, s3tables):
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
