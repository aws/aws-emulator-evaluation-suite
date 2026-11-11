"""associate-kms-key-nonexistent-log-group-fails."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-kms-key-nonexistent-log-group-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A real KMS key associates with an existing log group, while AssociateKmsKey with the same key on a
    missing group raises ResourceNotFoundException with its exact message and creates no group.
    """
    logs = ctx.client("logs")
    kms = ctx.client("kms")

    real_log_group = ctx.unique_name("sim2real-behav-real-lg-")
    logs.create_log_group(logGroupName=real_log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_log_group))

    missing_log_group = ctx.unique_name("sim2real-behav-missing-lg-")

    # AssociateKmsKey validates that the CloudWatch Logs service is actually
    # permitted to use the supplied key (via the key policy) before it gets
    # to checking whether the log group exists. A freshly created key with
    # only the default "root account" policy statement does not grant the
    # logs.<region>.amazonaws.com service principal any permissions, so the
    # call fails with an AccessDenied-style error from the KMS-side check
    # rather than the ResourceNotFoundException this check is targeting.
    # Attach a key policy that grants the CloudWatch Logs service the usage
    # permissions it needs so the only thing wrong with the request is the
    # missing log group.
    import json

    region = ctx.client("logs").meta.region_name
    account_id = ctx.account_id() if hasattr(ctx, "account_id") else None
    sts = ctx.client("sts")
    account_id = account_id or sts.get_caller_identity()["Account"]
    key_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRootAccountFullAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowCloudWatchLogsUseOfKey",
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
                },
            ],
        }
    )

    key_resp = kms.create_key(
        Description="sim2real behavioral fidelity check",
        Policy=key_policy,
        Tags=[
            {
                "TagKey": "sim2real",
                "TagValue": "logs-associate-kms-key-nonexistent-log-group",
            }
        ],
    )
    key_id = key_resp["KeyMetadata"]["KeyId"]
    real_kms_arn = key_resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    )

    # A freshly-attached key policy can take a few seconds to propagate on
    # the KMS side, so bound-poll past any transient permission errors.
    # Positive control: the same key, associated to a log group that
    # actually exists, must succeed -- and the association must show up on
    # an independent DescribeLogGroups read. This is what rules out a target
    # whose AssociateKmsKey simply always raises ResourceNotFoundException
    # without ever honouring a valid association.
    deadline = time.monotonic() + 30
    while True:
        try:
            logs.associate_kms_key(logGroupName=real_log_group, kmsKeyId=real_kms_arn)
            break
        except ClientError as err:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"positive control failed: AssociateKmsKey on an existing log group with "
                    f"a key policy that permits CloudWatch Logs should succeed, got {err!r}"
                ) from err
        time.sleep(2)

    control_described = logs.describe_log_groups(logGroupNamePrefix=real_log_group)[
        "logGroups"
    ][0]
    assert control_described.get("kmsKeyId") == real_kms_arn, (
        f"expected {real_log_group!r} to report kmsKeyId={real_kms_arn!r} after a "
        f"successful AssociateKmsKey, got {control_described.get('kmsKeyId')!r}"
    )

    # Negative: the identical key, but the log group name does not exist.
    deadline = time.monotonic() + 30
    code, message = _error(
        lambda: logs.associate_kms_key(logGroupName=missing_log_group, kmsKeyId=real_kms_arn)
    )
    while code != "ResourceNotFoundException" and time.monotonic() < deadline:
        time.sleep(2)
        code, message = _error(
            lambda: logs.associate_kms_key(logGroupName=missing_log_group, kmsKeyId=real_kms_arn)
        )

    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for AssociateKmsKey on a nonexistent "
        f"log group, got {code}"
    )
    expected_message = "The specified log group does not exist."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the rejected call must not have created the missing log
    # group as a side effect.
    absent = logs.describe_log_groups(logGroupNamePrefix=missing_log_group)[
        "logGroups"
    ]
    assert absent == [], (
        f"expected no log group named {missing_log_group!r} after a rejected "
        f"AssociateKmsKey, found {absent!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
