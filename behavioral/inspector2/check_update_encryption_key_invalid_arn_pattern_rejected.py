"""update-encryption-key-invalid-arn-pattern-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-encryption-key-invalid-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["inspector2"]

_SCAN_TYPE = "CODE"
_RESOURCE_TYPE = "AWS_LAMBDA_FUNCTION"
_ENABLE_RESOURCE_TYPE = "LAMBDA_CODE"
_BAD_ARN = "not-a-valid-kms-arn"
_BAD_ARN_MESSAGE = (
    "1 validation error detected: Value at 'kmsKeyId' failed to satisfy constraint: Member must "
    "satisfy regular expression pattern: arn:aws(-(us-gov|cn))?:kms:([a-z0-9][-.a-z0-9]{0,62})?:"
    "[0-9]{12}?:key/(([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    "|(mrk-[0-9a-zA-Z]{32}))"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:inspector2", "resource:account-singleton:inspector2-encryption-key")
def run(ctx) -> None:
    """UpdateEncryptionKey with a malformed kmsKeyId fails with ValidationException and its exact
    message both before and after a real customer key is configured, and the configured key stays
    unchanged."""
    inspector2 = ctx.client("inspector2")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    region = inspector2.meta.region_name

    was_enabled = _resource_status(inspector2, account_id) == "ENABLED"
    baseline_key = _get_key_or_none(inspector2)

    def _restore():
        if baseline_key is not None:
            _retry_while_not_enabled(
                inspector2,
                lambda: inspector2.update_encryption_key(
                    kmsKeyId=baseline_key, scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE
                ),
            )
        else:
            _retry_while_not_enabled(
                inspector2,
                lambda: inspector2.reset_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE),
            )
        if not was_enabled:
            inspector2.disable(resourceTypes=[_ENABLE_RESOURCE_TYPE])

    ctx.on_cleanup(_restore)

    # Beat 1: while LAMBDA_CODE is disabled, the malformed ARN is still rejected as a shape error
    # rather than an "not enabled" access error -- shape validation precedes the enablement check.
    # (Reading baseline_key above enables LAMBDA_CODE as a side effect, so unconditionally disable
    # here regardless of the original was_enabled state.)
    inspector2.disable(resourceTypes=[_ENABLE_RESOURCE_TYPE])
    _wait_disabled(inspector2, account_id)

    code, msg = _client_error_code(
        lambda: inspector2.update_encryption_key(
            kmsKeyId=_BAD_ARN, scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed ARN while LAMBDA_CODE is disabled, got {code!r}"
    )
    assert msg == _BAD_ARN_MESSAGE, msg

    # Positive control on the SAME operation: a real, well-formed key is accepted once enabled --
    # this is what tells "rejects this malformed ARN" apart from "rejects every UpdateEncryptionKey
    # call". The terminal read is GetEncryptionKey, independent of the mutating call.
    key_arn = _create_kms_key(ctx, kms, account_id, region, caller_arn)
    _retry_while_not_enabled(
        inspector2,
        lambda: inspector2.update_encryption_key(
            kmsKeyId=key_arn, scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE
        ),
    )
    # Teardown is LIFO: detach the key before its scheduled deletion runs, since a key pending
    # deletion can no longer be reset away.
    ctx.on_cleanup(
        lambda: _retry_while_not_enabled(
            inspector2,
            lambda: inspector2.reset_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE),
        )
    )
    got = inspector2.get_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE)
    assert got["kmsKeyId"] == key_arn, f"expected {key_arn}, got {got['kmsKeyId']}"

    # Beat 2: with LAMBDA_CODE enabled and a real key already configured, the same malformed ARN
    # is rejected again, and the configured key is unchanged -- read independently at the
    # destination, not from the failing call's own response.
    code, msg = _client_error_code(
        lambda: inspector2.update_encryption_key(
            kmsKeyId=_BAD_ARN, scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed ARN while enabled, got {code!r}"
    )
    assert msg == _BAD_ARN_MESSAGE, msg
    got = inspector2.get_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE)
    assert got["kmsKeyId"] == key_arn, (
        f"a rejected UpdateEncryptionKey call must not change the configured key; expected "
        f"{key_arn}, got {got['kmsKeyId']}"
    )


def _resource_status(inspector2, account_id: str) -> str:
    resp = inspector2.batch_get_account_status(accountIds=[account_id])
    accounts = resp["accounts"]
    assert len(accounts) == 1, f"expected exactly one account in response, got {len(accounts)}"
    return accounts[0]["resourceState"]["lambdaCode"]["status"]


def _get_key_or_none(inspector2):
    """GetEncryptionKey itself requires LAMBDA_CODE enabled (an unrelated AccessDeniedException
    otherwise masks the ResourceNotFoundException boundary), so read it through the same
    enable-and-retry helper used for the mutating call."""
    from botocore.exceptions import ClientError

    def _read():
        try:
            return inspector2.get_encryption_key(scanType=_SCAN_TYPE, resourceType=_RESOURCE_TYPE)["kmsKeyId"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise

    return _retry_while_not_enabled(inspector2, _read)


def _retry_while_not_enabled(inspector2, fn, *, timeout_s: float = 240, interval_s: float = 5):
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


def _wait_disabled(inspector2, account_id, *, timeout_s: float = 240, interval_s: float = 5):
    """Poll until LAMBDA_CODE reaches the terminal DISABLED state; a re-enable issued while it is
    still DISABLING does not take."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _resource_status(inspector2, account_id)
        if last == "DISABLED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached DISABLED within {timeout_s}s; last saw {last!r}")


def _client_error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected UpdateEncryptionKey to reject this call, but it SUCCEEDED and returned {result!r}")


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
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


