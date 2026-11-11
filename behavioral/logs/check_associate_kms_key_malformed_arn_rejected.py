"""associate-kms-key-malformed-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "associate-kms-key-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateKmsKey with a syntactically invalid key ARN raises InvalidParameterException with its exact
    message and leaves kmsKeyId unset; a real KMS key ARN then associates and DescribeLogGroups reports it."""
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    group_name = ctx.unique_name("sim2real-behav-akm-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    malformed_arn = "not-a-valid-kms-key-arn"
    code, message = _error(
        lambda: logs.associate_kms_key(logGroupName=group_name, kmsKeyId=malformed_arn)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "The specified KMS Key Id could not be found."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # (b) effect absent: the log group has no kmsKeyId set
    desc = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]
    assert "kmsKeyId" not in desc, f"expected no kmsKeyId, found {desc.get('kmsKeyId')}"

    # (c) positive control: a real, valid KMS key ARN associates successfully.
    # AssociateKmsKey requires the key policy to grant the CloudWatch Logs
    # service principal permission to use the key (this is not implied by the
    # default "root can do anything" key policy), so the key is created with
    # that statement up front. A freshly created key can also take a few
    # seconds to propagate before cross-service calls can resolve it, so poll
    # (bounded) past that instead of asserting on the first attempt.
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
        Description="sim2real-behav-akm-test-key",
        Policy=json.dumps(key_policy),
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.associate_kms_key(logGroupName=group_name, kmsKeyId=key_arn)
            break
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    else:
        raise AssertionError(f"GOT={last_err.response['Error']['Code'] if last_err else None}")
    ctx.on_cleanup(lambda: logs.disassociate_kms_key(logGroupName=group_name))
    desc = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0]
    assert desc.get("kmsKeyId") == key_arn, (
        f"expected kmsKeyId={key_arn!r} after associating a valid key, found {desc.get('kmsKeyId')!r}"
    )


def _error(fn):
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
