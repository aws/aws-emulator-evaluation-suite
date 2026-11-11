"""associate-kms-key-then-disassociate."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "associate-kms-key-then-disassociate"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateKmsKey attaches a KMS key to a log group and DisassociateKmsKey removes it, with
    DescribeLogGroups reporting the key ARN and then no kmsKeyId."""
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-kmsassoc-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": "associate-kms-key-then-disassociate"})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: logs.delete_log_group(logGroupName=name)))

    # AssociateKmsKey is denied (AccessDeniedException) unless the key policy grants the
    # regional logs service principal; the retry below covers key-policy propagation.
    key_policy = {
        "Version": "2012-10-17",
        "Id": "key-default-1",
        "Statement": [
            {
                "Sid": "EnableIAMUserPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchLogs",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": [
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                "Resource": "*",
                "Condition": {
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{ctx.region}:{account_id}:*"
                    }
                },
            },
        ],
    }

    key = kms.create_key(
        Description=f"sim2real key for {name}",
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "associate-kms-key-then-disassociate"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]

    def _cleanup_key():
        _ignore_not_found(lambda: kms.disable_key(KeyId=key_id))
        _ignore_not_found(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    ctx.on_cleanup(_cleanup_key)

    def _current_kms_key_id():
        resp = logs.describe_log_groups(logGroupNamePrefix=name)
        groups = [g for g in resp.get("logGroups", []) if g["logGroupName"] == name]
        assert groups, f"log group {name} disappeared"
        return groups[0].get("kmsKeyId")

    _retry_on_access_denied(
        lambda: logs.associate_kms_key(logGroupName=name, kmsKeyId=key_arn),
        timeout_s=60,
        interval_s=3,
    )
    associated = _poll_until(_current_kms_key_id, lambda v: v == key_arn, timeout_s=60, interval_s=3)
    assert associated == key_arn, f"expected kmsKeyId {key_arn}, got {associated}"

    logs.disassociate_kms_key(logGroupName=name)
    disassociated = _poll_until(_current_kms_key_id, lambda v: v is None, timeout_s=60, interval_s=3)
    assert disassociated is None, f"expected kmsKeyId cleared, got {disassociated}"


# ===== helpers =====
def _ignore_not_found(fn):
    """Run a teardown call; return only when the resource is already gone (or the key is
    already pending deletion) and raise every other error."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code")
        if code not in ("ResourceNotFoundException", "NotFoundException", "KMSInvalidStateException"):
            raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_on_access_denied(fn, *, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
