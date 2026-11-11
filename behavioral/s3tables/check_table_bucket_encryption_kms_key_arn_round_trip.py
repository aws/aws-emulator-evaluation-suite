"""table-bucket-encryption-kms-key-arn-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "table-bucket-encryption-kms-key-arn-round-trip"
GROUP = "representation"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A customer-managed KMS key ARN set as the default encryption for a table bucket
    via PutTableBucketEncryption is persisted and returned unchanged (exact ARN string,
    exact sseAlgorithm) by GetTableBucketEncryption."""
    kms = ctx.client("kms")
    s3tables = ctx.client("s3tables")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccountAccess",
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
            },
        ],
    }
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-s3t-kms-"),
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "s3t-kms-key-arn-round-trip"}],
    )
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
    )

    bucket_name = ctx.unique_name("sim2real-s3t-kmsenc-")
    bucket_arn = s3tables.create_table_bucket(
        name=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-kmsenc"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    s3tables.put_table_bucket_encryption(
        tableBucketARN=bucket_arn,
        encryptionConfiguration={"sseAlgorithm": "aws:kms", "kmsKeyArn": key_arn},
    )

    encryption = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert encryption["sseAlgorithm"] == "aws:kms", (
        f"expected sseAlgorithm 'aws:kms', got {encryption['sseAlgorithm']!r}"
    )
    assert encryption["kmsKeyArn"] == key_arn, (
        f"kmsKeyArn drifted: expected {key_arn!r}, got {encryption['kmsKeyArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
