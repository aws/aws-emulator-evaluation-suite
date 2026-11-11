"""delete-table-bucket-encryption-with-active-tables-succeeds."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delete-table-bucket-encryption-with-active-tables-succeeds"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTableBucketEncryption succeeds while a table created under the bucket's aws:kms default exists:
    the bucket default reads AES256 afterwards, while the table keeps aws:kms with the same kmsKeyArn,
    because the bucket setting applies only to tables created later."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    kms_key_arn = _get_or_create_kms_key(ctx, bucket_arn)
    s3tables.put_table_bucket_encryption(
        tableBucketARN=bucket_arn,
        encryptionConfiguration={"sseAlgorithm": "aws:kms", "kmsKeyArn": kms_key_arn},
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

    # the table inherited SSE-KMS from the bucket default at creation time
    table_enc_before = s3tables.get_table_encryption(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name
    )
    algo_before = table_enc_before["encryptionConfiguration"]["sseAlgorithm"]
    assert algo_before == "aws:kms", (
        f"expected table to inherit aws:kms from the bucket default, got {algo_before!r}"
    )

    # removing the bucket's default encryption succeeds even with an active table
    # relying on the setting it inherited
    s3tables.delete_table_bucket_encryption(tableBucketARN=bucket_arn)

    # the bucket-level default reverts to SSE-S3 for future tables
    bucket_enc_after = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    bucket_algo_after = bucket_enc_after["encryptionConfiguration"]["sseAlgorithm"]
    assert bucket_algo_after == "AES256", (
        f"expected bucket default to revert to AES256, got {bucket_algo_after!r}"
    )

    # but the existing table's own encryption metadata is untouched -- it keeps
    # the SSE-KMS configuration it inherited at creation time, it is not
    # retroactively reset to the new bucket default
    table_enc_after = s3tables.get_table_encryption(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name
    )
    table_cfg_after = table_enc_after["encryptionConfiguration"]
    assert table_cfg_after["sseAlgorithm"] == "aws:kms", (
        f"expected table's own encryption to stay aws:kms after the bucket default "
        f"reverted, got {table_cfg_after['sseAlgorithm']!r}"
    )
    assert table_cfg_after["kmsKeyArn"] == kms_key_arn, (
        f"expected table's own kmsKeyArn to stay {kms_key_arn!r}, "
        f"got {table_cfg_after.get('kmsKeyArn')!r}"
    )


def _create_table_bucket(ctx: Any) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-encconf-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _get_or_create_kms_key(ctx: Any, bucket_arn: str) -> str:
    import json

    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRootAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "EnableS3TablesMaintenance",
                    "Effect": "Allow",
                    "Principal": {"Service": "maintenance.s3tables.amazonaws.com"},
                    "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "kms:EncryptionContext:aws:s3:arn": f"{bucket_arn}/*"
                        }
                    },
                },
            ],
        }
    )
    key = kms.create_key(
        Description="sim2real-behav-s3tables encryption test key",
        Policy=policy,
        Tags=[{"TagKey": "sim2real-behav", "TagValue": "s3tables"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )
    return key["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
