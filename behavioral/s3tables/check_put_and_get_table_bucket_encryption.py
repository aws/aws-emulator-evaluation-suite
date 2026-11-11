"""put-and-get-table-bucket-encryption."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-and-get-table-bucket-encryption"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketEncryption persists an SSE configuration that GetTableBucketEncryption
    returns unchanged."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    s3t.put_table_bucket_encryption(
        tableBucketARN=bucket_arn,
        encryptionConfiguration={"sseAlgorithm": "AES256"},
    )

    resp = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    cfg = resp["encryptionConfiguration"]
    assert cfg["sseAlgorithm"] == "AES256", f"expected sseAlgorithm AES256, got {cfg}"
    assert "kmsKeyArn" not in cfg, f"expected no kmsKeyArn for AES256, got {cfg}"


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(
        name=name, tags={"sim2real:managed": "true", "sim2real:check": CHECK}
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
