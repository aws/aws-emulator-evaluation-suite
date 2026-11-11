"""encryption-kms-key-arn-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encryption-kms-key-arn-round-trip"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table bucket configured with SSE-KMS returns the exact same KMS key ARN
    (region, account, and key-id segments unchanged) on a subsequent
    GetTableBucketEncryption call.
    """
    s3tables = ctx.client("s3tables")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    key_policy = {
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
                "Sid": "AllowS3TablesMaintenance",
                "Effect": "Allow",
                "Principal": {"Service": "maintenance.s3tables.amazonaws.com"},
                "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-s3tables-key-"),
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: _schedule_key_deletion_quiet(kms, key["KeyId"]))

    bucket_arn = s3tables.create_table_bucket(
        name=ctx.unique_name("sim2real-kms-bucket-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3tables, bucket_arn))

    _retry_on_forbidden(
        lambda: s3tables.put_table_bucket_encryption(
            tableBucketARN=bucket_arn,
            encryptionConfiguration={"sseAlgorithm": "aws:kms", "kmsKeyArn": key_arn},
        )
    )

    got = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)["encryptionConfiguration"]
    assert got["sseAlgorithm"] == "aws:kms"
    assert got["kmsKeyArn"] == key_arn, f"kmsKeyArn drifted: expected {key_arn}, got {got['kmsKeyArn']}"

    # Region/account/key-id segments individually preserved.
    parts = key_arn.split(":")
    got_parts = got["kmsKeyArn"].split(":")
    assert parts[3] == got_parts[3], "region segment changed"
    assert parts[4] == got_parts[4], "account segment changed"
    assert parts[5] == got_parts[5], "key-id segment changed"


def _retry_on_forbidden(fn, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ForbiddenException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"KMS key never became usable for S3 Tables: {last_err}")


def _delete_bucket_quiet(s3tables, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket_encryption(tableBucketARN=bucket_arn)
    except s3tables.exceptions.NotFoundException:
        pass
    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except s3tables.exceptions.NotFoundException:
        pass


def _schedule_key_deletion_quiet(kms, key_id: str) -> None:
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except kms.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
