"""put-table-bucket-encryption-kms-missing-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-table-bucket-encryption-kms-missing-key-rejected"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketEncryption with sseAlgorithm=aws:kms and no kmsKeyArn is BadRequestException with the
    exact invalid-KMS-key-ARN message and leaves the bucket's encryption unchanged, while a later put
    with AES256 on the same bucket succeeds."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    baseline_code, baseline_cfg = _get_encryption(ctx, bucket_arn)

    code, message = _error(
        lambda: s3t.put_table_bucket_encryption(
            tableBucketARN=bucket_arn,
            encryptionConfiguration={"sseAlgorithm": "aws:kms"},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        "The specified KMS key ARN is invalid. Only key ARN format "
        "'arn:<partition>:kms:<region>:<account-id>:key/<key-id>' is supported."
    ), f"expected the exact invalid-KMS-key message, got {message!r}"

    after_code, after_cfg = _get_encryption(ctx, bucket_arn)
    assert after_code == baseline_code, f"expected encryption error code {baseline_code!r} unchanged, got {after_code!r}"
    assert after_cfg == baseline_cfg, f"expected encryption config {baseline_cfg!r} unchanged, got {after_cfg!r}"

    # Positive control: a valid AES256 configuration still succeeds on this bucket,
    # proving the rejection above is specific to the malformed KMS request, not a
    # broader outage of the encryption endpoint.
    s3t.put_table_bucket_encryption(
        tableBucketARN=bucket_arn,
        encryptionConfiguration={"sseAlgorithm": "AES256"},
    )
    got = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    assert got["encryptionConfiguration"]["sseAlgorithm"] == "AES256", (
        f"expected AES256 after positive control, got {got['encryptionConfiguration']!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name, tags={"sim2real-behav": "s3tables"})["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _get_encryption(ctx, bucket_arn: str):
    from botocore.exceptions import ClientError

    s3t = ctx.client("s3tables")
    try:
        resp = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)
        return None, resp.get("encryptionConfiguration")
    except ClientError as e:
        return e.response["Error"]["Code"], None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
