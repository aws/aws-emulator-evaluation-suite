"""kms-key-association-lifecycle-transitions."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "kms-key-association-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateKmsKey binds a KMS key for encryption-at-rest; DisassociateKmsKey
    removes it and a later re-associate succeeds cleanly."""
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    sts = ctx.client("sts")

    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(
        logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    # A CMK's default key policy only grants the account root full access;
    # CloudWatch Logs itself is not implicitly allowed to use it. Real AWS
    # enforces that the key policy explicitly grant the logs service the
    # encrypt/decrypt permissions scoped to log-group encryption contexts,
    # otherwise AssociateKmsKey fails with AccessDeniedException.
    key_policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-behav-logs-kms-policy",
        "Statement": [
            {
                "Sid": "EnableIamUserPermissions",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchLogs",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
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
                        "kms:EncryptionContext:aws:logs:arn": (
                            f"arn:aws:logs:{region}:{account_id}:log-group:*"
                        )
                    }
                },
            },
        ],
    }

    key = kms.create_key(
        Description="sim2real-behav logs kms association test",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "Sim2RealOwner", "TagValue": "behavioral-suite"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )

    def current_kms_key_id() -> str | None:
        groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
            "logGroups"
        ]
        for g in groups:
            if g["logGroupName"] == log_group_name:
                return g.get("kmsKeyId")
        return None

    # Associate: the log group's kmsKeyId should converge to the new key ARN.
    # A brand-new key policy can take a few seconds to propagate; retry on
    # AccessDeniedException (bounded) rather than treating it as fatal.
    _retry_until_success(
        lambda: logs.associate_kms_key(logGroupName=log_group_name, kmsKeyId=key_arn),
        retryable_codes={"AccessDeniedException"},
        timeout_s=60,
        interval_s=3,
    )
    associated = _poll_until(
        lambda: current_kms_key_id(), lambda v: v == key_arn, timeout_s=60, interval_s=2
    )
    assert associated == key_arn, f"expected kmsKeyId {key_arn}, got {associated}"

    # Disassociate: the binding should be removed.
    logs.disassociate_kms_key(logGroupName=log_group_name)
    disassociated = _poll_until(
        lambda: current_kms_key_id(), lambda v: v is None, timeout_s=60, interval_s=2
    )
    assert disassociated is None, (
        f"expected no kmsKeyId after disassociate, got {disassociated}"
    )

    # Re-associate: a fresh association must succeed cleanly (no stale-state error).
    logs.associate_kms_key(logGroupName=log_group_name, kmsKeyId=key_arn)
    reassociated = _poll_until(
        lambda: current_kms_key_id(), lambda v: v == key_arn, timeout_s=60, interval_s=2
    )
    assert reassociated == key_arn, f"re-associate did not converge, got {reassociated}"

    # Clean up the association before the log group cleanup fires.
    logs.disassociate_kms_key(logGroupName=log_group_name)


def _retry_until_success(fn, retryable_codes, *, timeout_s=60.0, interval_s=3.0):
    """Poll a dependent call to a success condition, retrying only on the
    given (transient/propagation-related) error codes, bounded by timeout_s."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # botocore.exceptions.ClientError
            response = getattr(exc, "response", None)
            code = (
                response.get("Error", {}).get("Code") if response is not None else None
            )
            if code not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    assert last_exc is not None, "retry loop exited without ever calling fn()"
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"condition not met within {timeout_s}s (last value: {last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
