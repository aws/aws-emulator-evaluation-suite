"""associate-kms-key-nonexistent-group-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-kms-key-nonexistent-group-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With a key whose policy grants CloudWatch Logs, AssociateKmsKey succeeds on an existing group but raises
    ResourceNotFoundException with its exact message for a missing group; once that group is created, the
    same call associates the key.
    """
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

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
        Description="sim2real key for associate-negative-test",
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "associate-kms-key-nonexistent-group-fails"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]

    def _cleanup_key():
        _quiet(lambda: kms.disable_key(KeyId=key_id))
        _quiet(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    ctx.on_cleanup(_cleanup_key)

    # Positive control: a real, pre-existing log group. This both proves the
    # key policy has propagated (so the negative below cannot be confused
    # with a masked AccessDeniedException) and proves AssociateKmsKey
    # succeeds in general against this key.
    control_group = ctx.unique_name("sim2real-kms-assoc-control-")
    logs.create_log_group(logGroupName=control_group)
    ctx.on_cleanup(lambda: _quiet(lambda: logs.delete_log_group(logGroupName=control_group)))

    _associate_past_key_propagation(logs, control_group, key_arn)

    control_described = logs.describe_log_groups(logGroupNamePrefix=control_group)["logGroups"]
    assert control_described and control_described[0].get("kmsKeyId") == key_arn, (
        f"positive control: expected describe_log_groups to reflect kmsKeyId={key_arn}, "
        f"got {control_described!r}"
    )

    # The negative: an independent read confirms the group is genuinely
    # absent, then AssociateKmsKey against it must fail specifically with
    # ResourceNotFoundException -- not merely "some error".
    missing_group = ctx.unique_name("sim2real-missing-loggroup-")
    ctx.on_cleanup(lambda: _quiet(lambda: logs.delete_log_group(logGroupName=missing_group)))

    absent_before = logs.describe_log_groups(logGroupNamePrefix=missing_group)["logGroups"]
    assert absent_before == [], f"expected {missing_group} to not exist yet, got {absent_before!r}"

    deadline = time.monotonic() + 60
    code, message = _error(
        lambda: logs.associate_kms_key(logGroupName=missing_group, kmsKeyId=key_arn)
    )
    while code == "AccessDeniedException" and time.monotonic() < deadline:
        time.sleep(3)
        code, message = _error(
            lambda: logs.associate_kms_key(logGroupName=missing_group, kmsKeyId=key_arn)
        )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "The specified log group does not exist."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Restore: create the exact log group the negative call named, then
    # reissue the identical AssociateKmsKey call. It must now succeed, and
    # the association must be visible at an independent read -- proving the
    # earlier ResourceNotFoundException tracked the group's absence and
    # nothing else about the request.
    logs.create_log_group(logGroupName=missing_group)

    _associate_past_key_propagation(logs, missing_group, key_arn)

    restored_described = logs.describe_log_groups(logGroupNamePrefix=missing_group)["logGroups"]
    assert restored_described and restored_described[0].get("kmsKeyId") == key_arn, (
        f"restore: expected describe_log_groups to reflect kmsKeyId={key_arn}, "
        f"got {restored_described!r}"
    )


def _error(fn):
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _quiet(fn):
    """Teardown only: run fn() and ignore a ClientError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "ResourceNotFoundException"):
            raise


def _associate_past_key_propagation(logs, group, key_arn, *, timeout_s=60.0, interval_s=3.0):
    """AssociateKmsKey must succeed; only an AccessDeniedException (key policy still
    propagating) is retried, bounded by timeout_s."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            logs.associate_kms_key(logGroupName=group, kmsKeyId=key_arn)
            return
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"AssociateKmsKey on {group} was still AccessDenied after {timeout_s}s: {err!r}"
                ) from err
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
