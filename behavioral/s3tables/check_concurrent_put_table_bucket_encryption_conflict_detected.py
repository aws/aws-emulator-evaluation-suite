"""concurrent-put-table-bucket-encryption-conflict-detected."""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-table-bucket-encryption-conflict-detected"
GROUP = "concurrency"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutTableBucketEncryption calls (SSE-S3 and SSE-KMS) on one table bucket both
    succeed, and the bucket ends with exactly one of the two configurations, never a mix such as
    aws:kms without the key or AES256 with a key."""
    s3tables = ctx.client("s3tables")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    bucket_arn = _create_table_bucket(ctx, s3tables)
    account_id = sts.get_caller_identity()["Account"]
    key_arn = _create_kms_key(ctx, kms, account_id)

    config_aes = {"sseAlgorithm": "AES256"}
    config_kms = {"sseAlgorithm": "aws:kms", "kmsKeyArn": key_arn}

    def _put(cfg):
        try:
            s3tables.put_table_bucket_encryption(
                tableBucketARN=bucket_arn, encryptionConfiguration=cfg
            )
            return "ok"
        except ClientError as err:
            return err.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result() for f in [pool.submit(_put, config_aes), pool.submit(_put, config_kms)]]

    assert all(r == "ok" for r in results), f"expected both concurrent puts to succeed, got {results}"

    final = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)[
        "encryptionConfiguration"
    ]
    matches_aes = final.get("sseAlgorithm") == "AES256" and not final.get("kmsKeyArn")
    matches_kms = final.get("sseAlgorithm") == "aws:kms" and final.get("kmsKeyArn") == key_arn
    assert matches_aes != matches_kms, (
        f"final encryption state is neither pure AES256 nor pure SSE-KMS (corrupted/merged): {final}"
    )


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_kms_key(ctx, kms, account_id: str) -> str:
    policy = {
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
                "Sid": "EnableS3TablesMaintenanceUsage",
                "Effect": "Allow",
                "Principal": {"Service": "maintenance.s3tables.amazonaws.com"},
                "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Policy=json.dumps(policy), Description="sim2real s3tables behavioral test key"
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
