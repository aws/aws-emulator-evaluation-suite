"""invalid-parameter-validation-on-create."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-parameter-validation-on-create"
GROUP = 'log-stream-lifecycle'
SERVICES = ['logs']


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


def _delete_log_group_if_present(svc, name):
    try:
        svc.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _describe_log_group(svc, name):
    desc = svc.describe_log_groups(logGroupNamePrefix=name)
    for g in desc.get("logGroups", []):
        if g["logGroupName"] == name:
            return g
    raise AssertionError(f"log group {name!r} not found via DescribeLogGroups")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """An invalid log group or stream name is rejected with InvalidParameterException and nothing
    is created; the surrounding stream, retention, KMS and delete operations behave as documented.
    """
    svc = ctx.client("logs")

    invalid_group_base = ctx.unique_name("sim2real-behav-lg-invalid-")
    invalid_group_name = f"{invalid_group_base} !!! "
    code_group, msg_group = _error_code(lambda: svc.create_log_group(logGroupName=invalid_group_name))
    assert code_group == "InvalidParameterException", (
        f"expected InvalidParameterException for an invalid log group name, got {code_group!r}"
    )
    expected = (
        "1 validation error detected: Value at 'logGroupName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [\\.\\-_/#A-Za-z0-9]+"
    )
    assert msg_group == expected, f"expected message {expected!r}, got {msg_group!r}"
    desc = svc.describe_log_groups(logGroupNamePrefix=invalid_group_base)
    assert desc.get("logGroups", []) == [], "invalid-name log group was created anyway"

    valid_group = ctx.unique_name("sim2real-behav-lg-validparent-")
    svc.create_log_group(logGroupName=valid_group)
    ctx.on_cleanup(lambda _n=valid_group: _delete_log_group_if_present(svc, _n))

    # Log stream names may not contain a colon (':').
    invalid_stream_name = f"invalid:stream:{ctx.unique_name('')}"
    code_stream, msg_stream = _error_code(
        lambda: svc.create_log_stream(logGroupName=valid_group, logStreamName=invalid_stream_name)
    )
    assert code_stream == "InvalidParameterException", (
        f"expected InvalidParameterException for a colon-containing log stream name, got {code_stream!r}"
    )
    expected = (
        "1 validation error detected: Value at 'logStreamName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [^:*]*"
    )
    assert msg_stream == expected, f"expected message {expected!r}, got {msg_stream!r}"
    desc_streams = svc.describe_log_streams(logGroupName=valid_group)
    assert desc_streams.get("logStreams", []) == [], "invalid-name log stream was created anyway"

    valid_stream = ctx.unique_name("sim2real-behav-stream-ok-")
    svc.create_log_stream(logGroupName=valid_group, logStreamName=valid_stream)
    svc.delete_log_stream(logGroupName=valid_group, logStreamName=valid_stream)
    desc_after_delete = svc.describe_log_streams(logGroupName=valid_group, logStreamNamePrefix=valid_stream)
    assert desc_after_delete.get("logStreams", []) == [], "log stream still listed after DeleteLogStream"

    # A deleted stream is unusable, not just unlisted.
    code_put_dead_stream, msg_put_dead_stream = _error_code(
        lambda: svc.put_log_events(
            logGroupName=valid_group,
            logStreamName=valid_stream,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": "after-delete"}],
        )
    )
    assert code_put_dead_stream == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException putting events to a deleted log stream, got {code_put_dead_stream!r}"
    )
    expected = "The specified log stream does not exist."
    assert msg_put_dead_stream == expected, f"expected message {expected!r}, got {msg_put_dead_stream!r}"

    svc.put_retention_policy(logGroupName=valid_group, retentionInDays=7)
    svc.delete_retention_policy(logGroupName=valid_group)
    desc_group = _describe_log_group(svc, valid_group)
    assert "retentionInDays" not in desc_group, "retentionInDays still present after DeleteRetentionPolicy"

    code_kms, msg_kms = _error_code(
        lambda: svc.associate_kms_key(logGroupName=valid_group, kmsKeyId="not-a-real-kms-key-arn")
    )
    assert code_kms == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed kmsKeyId, got {code_kms!r}"
    )
    expected = "The specified KMS Key Id could not be found."
    assert msg_kms == expected, f"expected message {expected!r}, got {msg_kms!r}"
    assert "kmsKeyId" not in _describe_log_group(svc, valid_group), "a malformed kmsKeyId was associated anyway"

    # Control: a real key whose policy grants the Logs service principal still associates.
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    key_policy = {
        "Version": "2012-10-17",
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
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description="sim2real-behav-invalid-param-test-key",
        Policy=json.dumps(key_policy),
    )["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # A new key takes a few seconds before a cross-service call can resolve it.
    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            svc.associate_kms_key(logGroupName=valid_group, kmsKeyId=key_arn)
            break
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    else:
        raise AssertionError(
            f"expected AssociateKmsKey with a valid key to eventually succeed, got {last_err}"
        )
    assert _describe_log_group(svc, valid_group).get("kmsKeyId") == key_arn, (
        "a valid kmsKeyId did not take effect after AssociateKmsKey"
    )

    svc.disassociate_kms_key(logGroupName=valid_group)
    assert "kmsKeyId" not in _describe_log_group(svc, valid_group), (
        "kmsKeyId still present after DisassociateKmsKey"
    )

    svc.delete_log_group(logGroupName=valid_group)
    desc_deleted = svc.describe_log_groups(logGroupNamePrefix=valid_group)
    assert desc_deleted.get("logGroups", []) == [], "log group still listed after DeleteLogGroup"

    code_create_on_dead_group, msg_create_on_dead_group = _error_code(
        lambda: svc.create_log_stream(logGroupName=valid_group, logStreamName=ctx.unique_name(""))
    )
    assert code_create_on_dead_group == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException creating a log stream on a deleted log group, got {code_create_on_dead_group!r}"
    )
    expected = "The specified log group does not exist."
    assert msg_create_on_dead_group == expected, (
        f"expected message {expected!r}, got {msg_create_on_dead_group!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
