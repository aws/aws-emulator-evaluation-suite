"""put-table-bucket-encryption-invalid-algorithm-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-encryption-invalid-algorithm-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketEncryption with an unsupported sseAlgorithm is BadRequestException "The specified SSE
    algorithm is invalid." and leaves the AES256 default in place, while a put with AES256 succeeds."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    code, message = _error(
        lambda: s3tables.put_table_bucket_encryption(
            tableBucketARN=bucket_arn,
            encryptionConfiguration={"sseAlgorithm": "des-not-a-real-algorithm"},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "The specified SSE algorithm is invalid.", (
        f"expected the exact invalid-algorithm message, got {message!r}"
    )

    # effect absent: the rejected call did not change the bucket's default
    # (S3 Tables buckets always have SSE-S3 as the baseline encryption)
    unchanged = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    unchanged_alg = unchanged["encryptionConfiguration"]["sseAlgorithm"]
    assert unchanged_alg == "AES256", f"expected default AES256 unchanged, got {unchanged_alg!r}"

    # positive control: a valid algorithm on the same bucket succeeds
    s3tables.put_table_bucket_encryption(
        tableBucketARN=bucket_arn, encryptionConfiguration={"sseAlgorithm": "AES256"}
    )
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket_encryption(tableBucketARN=bucket_arn))
    got = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    got_alg = got["encryptionConfiguration"]["sseAlgorithm"]
    assert got_alg == "AES256", f"expected positive control AES256, got {got_alg!r}"


def _create_table_bucket(ctx: Any) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-badalgo-")
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-badalgo"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


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
