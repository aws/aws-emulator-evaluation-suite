"""update-reset-encryption-key-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-reset-encryption-key-round-trip"
GROUP = "state"
SERVICES = ["inspector2"]

# Lambda code scanning is the encryption use case UpdateEncryptionKey/ResetEncryptionKey document
# using scanType=CODE, resourceType=AWS_LAMBDA_FUNCTION. It requires LAMBDA_CODE scanning to be
# enabled for the account.
_SCAN_TYPE = "CODE"
_RESOURCE_TYPE = "AWS_LAMBDA_FUNCTION"
_ENABLE_RESOURCE_TYPE = "LAMBDA_CODE"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:inspector2", "resource:account-singleton:inspector2-encryption-key")
def run(ctx) -> None:
    """UpdateEncryptionKey persists a custom KMS key; ResetEncryptionKey reverts to the AWS-owned default."""
    inspector2 = ctx.client("inspector2")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    region = inspector2.meta.region_name

    was_enabled = _resource_status(inspector2, account_id) == "ENABLED"

    def _restore_enablement():
        if not was_enabled:
            inspector2.disable(resourceTypes=[_ENABLE_RESOURCE_TYPE])

    ctx.on_cleanup(_restore_enablement)

    key_arn = _create_kms_key(ctx, kms, account_id, region, caller_arn)

    _retry_while_not_enabled(
        inspector2,
        lambda: inspector2.update_encryption_key(
            kmsKeyId=key_arn, scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE
        ),
    )
    ctx.on_cleanup(lambda: inspector2.reset_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE))

    got = inspector2.get_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE)
    assert got["kmsKeyId"] == key_arn, f"expected {key_arn}, got {got['kmsKeyId']}"

    inspector2.reset_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE)

    code, msg = _error_code(lambda: inspector2.get_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE))
    assert code == "ResourceNotFoundException", (
        f"expected GetEncryptionKey to fail with ResourceNotFoundException after reset (falls back to "
        f"the AWS-owned key), got {code!r}"
    )
    assert msg == "Customer managed KMS key not found", msg


def _resource_status(inspector2, account_id: str) -> str:
    resp = inspector2.batch_get_account_status(accountIds=[account_id])
    accounts = resp["accounts"]
    assert len(accounts) == 1, f"expected exactly one account in response, got {len(accounts)}"
    return accounts[0]["resourceState"]["lambdaCode"]["status"]


def _retry_while_not_enabled(inspector2, fn, *, timeout_s: float = 90, interval_s: float = 5):
    """Enable LAMBDA_CODE (idempotent, re-nudged each attempt to survive contention with other
    concurrently running checks toggling the same account-level setting) and retry fn() until it
    stops reporting the account as not-enabled."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            inspector2.enable(resourceTypes=[_ENABLE_RESOURCE_TYPE])
        except ClientError:
            pass
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "AccessDeniedException" and "not enabled" in msg.lower():
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"account never reached LAMBDA_CODE enabled within {timeout_s}s: {last_exc}")


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _key_policy(account_id: str, region: str, caller_arn: str) -> str:
    """KMS key policy granting Inspector2/Amazon Q the permissions documented for Lambda code
    scanning encryption with a customer managed key, plus full root access for cleanup."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableRootPermissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowQDataKeyUsage",
                    "Effect": "Allow",
                    "Principal": {"Service": "q.amazonaws.com"},
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:GenerateDataKey",
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "kms:EncryptionContext:aws:qdeveloper:lambda-codescan-scope": account_id
                        },
                        "StringEquals": {"aws:SourceAccount": account_id},
                        "ArnLike": {"aws:SourceArn": f"arn:aws:qdeveloper:{region}:{account_id}:scans/*"},
                    },
                },
                {
                    "Sid": "AllowQDescribeKey",
                    "Effect": "Allow",
                    "Principal": {"Service": "q.amazonaws.com"},
                    "Action": "kms:DescribeKey",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account_id},
                        "ArnLike": {"aws:SourceArn": f"arn:aws:qdeveloper:{region}:{account_id}:scans/*"},
                    },
                },
                {
                    "Sid": "AllowCallerDataKeyUsageViaInspector2",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:GenerateDataKey",
                    ],
                    "Principal": {"AWS": caller_arn},
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"kms:ViaService": f"inspector2.{region}.amazonaws.com"},
                        "StringLike": {
                            "kms:EncryptionContext:aws:qdeveloper:lambda-codescan-scope": account_id
                        },
                    },
                },
                {
                    "Sid": "AllowCallerDescribeKeyViaInspector2",
                    "Effect": "Allow",
                    "Action": ["kms:DescribeKey"],
                    "Principal": {"AWS": caller_arn},
                    "Resource": "*",
                    "Condition": {"StringEquals": {"kms:ViaService": f"inspector2.{region}.amazonaws.com"}},
                },
            ],
        }
    )


def _create_kms_key(ctx, kms, account_id: str, region: str, caller_arn: str) -> str:
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-inspector2-key-"),
        Policy=_key_policy(account_id, region, caller_arn),
        Tags=[{"TagKey": "sim2real", "TagValue": "update-reset-encryption-key-round-trip"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)



