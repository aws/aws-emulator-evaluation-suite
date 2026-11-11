"""associate-kms-key-without-service-permission-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "associate-kms-key-without-service-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateKmsKey with a key whose policy grants CloudWatch Logs nothing raises AccessDeniedException with
    its exact message and leaves kmsKeyId unset; a key whose policy grants the service associates."""
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    log_group_name, log_group_arn = _create_log_group(ctx)

    # Key policy WITHOUT any statement granting the CloudWatch Logs service principal access.
    bad_key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccessOnly",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }
    bad_key = kms.create_key(
        Policy=json.dumps(bad_key_policy),
        Description=ctx.unique_name("sim2real-behav-badkey-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    bad_key_arn = bad_key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=bad_key_arn, PendingWindowInDays=7))

    # The key is enabled but its policy grants no permission at all to the CloudWatch Logs
    # service principal. AssociateKmsKey actively validates that grant (not merely at first
    # use), so this is rejected durably -- retry only to absorb incidental transient errors, not
    # because the rejection itself is expected to clear.
    code, message = _error_with_retry(
        lambda: logs.associate_kms_key(logGroupName=log_group_name, kmsKeyId=bad_key_arn),
        "AccessDeniedException",
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = (
        "The specified KMS key does not exist or is not allowed to be used with Arn "
        f"'{log_group_arn}'"
    )
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    described = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    matching = [g for g in described if g["logGroupName"] == log_group_name]
    assert len(matching) == 1, f"expected exactly one log group named {log_group_name!r}, found {len(matching)}"
    assert "kmsKeyId" not in matching[0], "kmsKeyId must not be set after a rejected association"

    # Positive control: a key policy that DOES grant the CloudWatch Logs service permission
    # associates successfully.
    good_key_policy = {
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
            },
        ],
    }
    good_key = kms.create_key(
        Policy=json.dumps(good_key_policy),
        Description=ctx.unique_name("sim2real-behav-goodkey-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    good_key_arn = good_key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=good_key_arn, PendingWindowInDays=7))

    _associate_with_retry(logs, log_group_name, good_key_arn)
    described_after = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    matching_after = [g for g in described_after if g["logGroupName"] == log_group_name]
    assert matching_after[0]["kmsKeyId"] == good_key_arn, (
        f"expected kmsKeyId {good_key_arn!r} after a permitted association, "
        f"got {matching_after[0].get('kmsKeyId')!r}"
    )


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_with_retry(fn, expected_code, timeout_s=60.0, interval_s=3.0):
    """Call fn() until it is rejected with expected_code or timeout_s passes; return the last
    (Code, Message). A success raises at once: AWS rejects this call durably, so a target that
    accepts it fails loudly instead of reading as a code mismatch."""
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            error = e.response.get("Error", {})
            code, message = error.get("Code"), error.get("Message")
            if code == expected_code or time.monotonic() >= deadline:
                return code, message
        else:
            raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")
        time.sleep(interval_s)


def _create_log_group(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=name)))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{name}"
    return name, arn


def _associate_with_retry(logs, log_group_name, key_arn, timeout_s=30.0, interval_s=5.0):
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.associate_kms_key(logGroupName=log_group_name, kmsKeyId=key_arn)
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] != "InvalidParameterException":
                raise
            time.sleep(interval_s)
    raise AssertionError(f"AssociateKmsKey never succeeded (key-policy propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
