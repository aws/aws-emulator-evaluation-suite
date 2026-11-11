"""associate-kms-key-invalid-key-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-kms-key-invalid-key-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateKmsKey with a non-KMS ARN raises InvalidParameterException with its exact message and leaves
    kmsKeyId unset; a real KMS key ARN then associates and DescribeLogGroups reports it."""
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    name = ctx.unique_name("sim2real-behav-kms-")
    logs.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))

    bogus_key_ids = [
        "not-an-arn-at-all",
        "arn:aws:s3:::some-bucket",  # syntactically an ARN, but not a KMS key
    ]
    for bogus in bogus_key_ids:
        code, message = _error(lambda k=bogus: logs.associate_kms_key(logGroupName=name, kmsKeyId=k))
        assert code == "InvalidParameterException", (
            f"expected InvalidParameterException for kmsKeyId={bogus!r}, got {code!r}"
        )
        expected_message = "The specified KMS Key Id could not be found."
        assert message == expected_message, (
            f"expected the exact message {expected_message!r}, got {message!r}"
        )

    # Effect absent: neither rejected attempt left a kmsKeyId behind.
    described = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    assert described, f"expected log group {name!r} to exist"
    assert "kmsKeyId" not in described[0], (
        f"expected no kmsKeyId after rejected associations, found {described[0].get('kmsKeyId')!r}"
    )

    # Positive control: a real, valid KMS key ARN still associates successfully.
    # AssociateKmsKey requires the key policy to grant the CloudWatch Logs service
    # principal permission to use the key, and a freshly created key can take a few
    # seconds to propagate, so poll (bounded) past that instead of asserting on the
    # first attempt.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
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
        Description=ctx.unique_name("sim2real-behav-kms-key-"),
        Policy=json.dumps(key_policy),
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.associate_kms_key(logGroupName=name, kmsKeyId=key_arn)
            break
        except ClientError as err:
            last_err = err
            time.sleep(3.0)
    else:
        raise AssertionError(
            "AssociateKmsKey never succeeded with a valid key (propagation?): "
            f"{last_err.response['Error']['Code'] if last_err else None}"
        )
    ctx.on_cleanup(lambda: logs.disassociate_kms_key(logGroupName=name))

    described_after = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    assert described_after and described_after[0].get("kmsKeyId") == key_arn, (
        f"expected kmsKeyId={key_arn!r} after positive control, "
        f"got {described_after[0].get('kmsKeyId') if described_after else None!r}"
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
