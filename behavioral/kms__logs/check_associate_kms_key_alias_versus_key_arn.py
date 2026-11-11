"""associate-kms-key-alias-versus-key-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-kms-key-alias-versus-key-arn"
GROUP = "kms-key-identifier-format"
SERVICES = ["kms", "logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateKmsKey rejects a bare KMS alias name with InvalidParameterException and leaves the
    group unencrypted, while the same key's ARN is accepted and becomes the group's kmsKeyId.
    The key policy admits CloudWatch Logs for this group, so only identifier resolution differs.
    """
    logs = ctx.client("logs")
    kms = ctx.client("kms")

    group = ctx.unique_name("sim2real-xsvc-lg-akv-")
    group_arn = f"arn:aws:logs:{ctx.region}:{ctx.account}:log-group:{group}"

    key_arn, key_id = _create_logs_key(ctx, kms, group_arn)
    alias_name = ctx.unique_name("alias/sim2real-xsvc-akv-")
    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: _quiet(lambda: kms.delete_alias(AliasName=alias_name),
                                  "NotFoundException"))

    _create_log_group(ctx, logs, group)

    # The Smithy model puts no pattern on kmsKeyId, only a length bound.
    code, message = _error(lambda: logs.associate_kms_key(
        logGroupName=group, kmsKeyId=alias_name))
    assert code == "InvalidParameterException", (
        f"AssociateKmsKey with a bare alias name must be rejected with "
        f"InvalidParameterException; got {code!r} ({message!r})"
    )
    want = "The specified KMS Key Id could not be found."
    assert message == want, f"expected message {want!r}, got {message!r}"
    assert _kms_key_of(logs, group) is None, (
        f"a rejected AssociateKmsKey must leave the group unencrypted; kmsKeyId is "
        f"{_kms_key_of(logs, group)!r}"
    )

    # Policy propagation on a new key can lag, so the transient code is retried, bounded; the
    # alias rejection above raises the same code and is asserted before this retry.
    _retry_code(
        lambda: logs.associate_kms_key(logGroupName=group, kmsKeyId=key_arn),
        "InvalidParameterException", timeout_s=120.0,
        description=f"AssociateKmsKey {group!r} with its key ARN {key_arn!r}",
    )
    associated = _kms_key_of(logs, group)
    assert associated == key_arn, (
        f"after a successful association kmsKeyId must be {key_arn!r}; got {associated!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call was expected to be rejected but SUCCEEDED")


def _retry_code(fn, transient_code, *, timeout_s, description):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != transient_code or time.monotonic() >= deadline:
                raise AssertionError(f"{description} failed: {exc.response['Error']!r}") from exc
            time.sleep(5.0)


def _kms_key_of(logs, group):
    found = [g for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
             if g["logGroupName"] == group]
    assert len(found) == 1, f"expected exactly one log group named {group!r}, found {len(found)}"
    return found[0].get("kmsKeyId")


def _quiet(fn, *ok_codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ok_codes:
            raise


def _create_logs_key(ctx, kms, group_arn):
    """Create a CMK usable by CloudWatch Logs only for ``group_arn``.

    Its cleanup is registered first, so LIFO runs it after the alias and log group are gone.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AccountAdmin", "Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "CloudWatchLogsForOneGroup", "Effect": "Allow",
             "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
             "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                        "kms:GenerateDataKey*", "kms:Describe*"],
             "Resource": "*",
             "Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": group_arn}}},
        ],
    }
    key = kms.create_key(
        Policy=json.dumps(policy),
        Description=ctx.unique_name("sim2real-xsvc-logs-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_arn, key_id = key["Arn"], key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))
    return key_arn, key_id


def _create_log_group(ctx, logs, group, **kwargs):
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK}, **kwargs)

    def _teardown():
        # DisassociateKmsKey BEFORE the group goes, and both before the key is scheduled.
        _quiet(lambda: logs.disassociate_kms_key(logGroupName=group), "ResourceNotFoundException")
        _quiet(lambda: logs.delete_log_group(logGroupName=group), "ResourceNotFoundException")

    ctx.on_cleanup(_teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
