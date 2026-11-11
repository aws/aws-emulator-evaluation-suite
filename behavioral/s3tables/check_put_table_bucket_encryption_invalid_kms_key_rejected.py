"""put-table-bucket-encryption-invalid-kms-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-encryption-invalid-kms-key-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Supplying a malformed KMS key ARN to SSE-KMS bucket encryption is rejected with
    BadRequestException, and the malformed configuration is never persisted."""
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-kms-")
    bucket_arn = s3t.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-kms"},
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=bucket_arn))

    malformed_kms_arn = "not-a-valid-kms-key-arn"
    code, message = _error(
        lambda: s3t.put_table_bucket_encryption(
            tableBucketARN=bucket_arn,
            encryptionConfiguration={"sseAlgorithm": "aws:kms", "kmsKeyArn": malformed_kms_arn},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        "The specified KMS key ARN is invalid. Only key ARN format "
        "'arn:<partition>:kms:<region>:<account-id>:key/<key-id>' is supported."
    ), f"expected the exact invalid-KMS-key message, got {message!r}"

    # effect absent: a fresh bucket already has default SSE-S3 encryption active (real AWS
    # never 404s here), so the rejected write must leave that default
    # in place rather than persisting the malformed KMS configuration.
    after = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert after.get("sseAlgorithm") == "AES256", f"expected AES256 default unchanged, got {after}"
    assert not after.get("kmsKeyArn"), f"expected no kmsKeyArn persisted, got {after.get('kmsKeyArn')!r}"

    # positive control: a valid encryption configuration on the same bucket succeeds
    s3t.put_table_bucket_encryption(
        tableBucketARN=bucket_arn, encryptionConfiguration={"sseAlgorithm": "AES256"}
    )
    got = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    got_alg = got["encryptionConfiguration"]["sseAlgorithm"]
    assert got_alg == "AES256", f"expected AES256 after positive control, got {got_alg!r}"


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
