"""get-human-readable-summary."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-human-readable-summary"
GROUP = 'account_summary'
SERVICES = ['iam']

TRUST_POLICY_EC2 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetHumanReadableSummary rejects a valid role ARN with ValidationError "Invalid resource type
    in ARN", and a never-created delegation-request ARN with NoSuchEntity."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("hrsrole-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=TRUST_POLICY_EC2)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    code_wrong_type, message = _error(lambda: iam.get_human_readable_summary(EntityArn=role_arn))
    assert code_wrong_type == "ValidationError", (
        f"expected ValidationError for a wrong-resource-type EntityArn (role), got {code_wrong_type}"
    )
    expected = "Invalid resource type in ARN"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # CreateDelegationRequest is not available for general use, so the success path is not tested.
    account = ctx.client("sts").get_caller_identity()["Account"]
    missing_id = ctx.unique_name("missing-")
    fake_delegation_arn = f"arn:aws:iam::{account}:delegation-request/{missing_id}"
    code_missing, message = _error(
        lambda: iam.get_human_readable_summary(EntityArn=fake_delegation_arn)
    )
    assert code_missing == "NoSuchEntity", (
        f"expected NoSuchEntity for a never-created delegation-request EntityArn, got {code_missing}"
    )
    expected = f"DelegationRequest not found: {missing_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
