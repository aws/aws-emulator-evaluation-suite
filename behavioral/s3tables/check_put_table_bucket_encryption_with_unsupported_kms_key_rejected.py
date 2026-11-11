"""put-table-bucket-encryption-with-unsupported-kms-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-encryption-with-unsupported-kms-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketEncryption with an unrelated/inaccessible KMS key ARN is rejected, not stored."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    baseline = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert baseline["sseAlgorithm"] == "AES256", f"expected AES256 default, got {baseline}"

    # An ARN pointing at a KMS key in an unrelated account/region the caller cannot access.
    # S3 Tables checks access to the referenced key and denies the request rather than
    # storing an unusable encryption configuration.
    bogus_kms_arn = f"arn:aws:kms:{ctx.region}:111122223333:key/00000000-0000-0000-0000-000000000000"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    code, message = _error(
        lambda: s3tables.put_table_bucket_encryption(
            tableBucketARN=bucket_arn,
            encryptionConfiguration={"sseAlgorithm": "aws:kms", "kmsKeyArn": bogus_kms_arn},
        )
    )
    assert code == "ForbiddenException", f"code={code}"
    expected = (
        f"User: {caller_arn} is not authorized to perform: kms:DescribeKey on this resource "
        "because the resource does not exist in this Region, no resource-based policies allow "
        "access, or a resource-based policy explicitly denies access"
    )
    assert message == expected, f"message={message!r}"

    # effect absent: the bucket's default encryption is still SSE-S3, not the rejected KMS config
    after = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert after.get("sseAlgorithm") == "AES256", f"expected AES256 unchanged, got {after}"
    assert not after.get("kmsKeyArn"), f"expected no kmsKeyArn persisted, got {after.get('kmsKeyArn')!r}"

    # positive control: a valid (non-KMS) encryption update is accepted and persists
    s3tables.put_table_bucket_encryption(
        tableBucketARN=bucket_arn, encryptionConfiguration={"sseAlgorithm": "AES256"}
    )
    confirmed = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert confirmed["sseAlgorithm"] == "AES256", f"expected AES256 after positive control, got {confirmed}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
