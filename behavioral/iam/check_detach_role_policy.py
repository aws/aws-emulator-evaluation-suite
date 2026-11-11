"""detach-role-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

MINIMAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

MINIMAL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:GetUser",
                "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
            }
        ],
    }
)

CHECK = "detach-role-policy"
GROUP = 'attach_detach'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachRolePolicy removes the attachment; a repeat detach on the same pair is NoSuchEntity."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=[{"Key": "sim2real-behav", "Value": "detach-role-policy"}],
    )
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=MINIMAL_POLICY_DOCUMENT,
        Path="/",
        Tags=[{"Key": "sim2real-behav", "Value": "detach-role-policy"}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
    iam.attach_role_policy(RoleName=role, PolicyArn=arn)

    def _detach_if_attached(r=role, p=arn):
        try:
            iam.detach_role_policy(RoleName=r, PolicyArn=p)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_detach_if_attached)

    before = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]]
    assert arn in before, f"expected {arn} attached before detach, got {before}"

    iam.detach_role_policy(RoleName=role, PolicyArn=arn)
    after = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]]
    assert arn not in after, f"expected {arn} absent from attached policies after detach, got {after}"

    try:
        iam.detach_role_policy(RoleName=role, PolicyArn=arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchEntity", f"expected NoSuchEntity detaching an already-detached policy, got {code}"
        msg = exc.response["Error"].get("Message")
        assert msg == f"Policy {arn} was not found.", f"unexpected error message {msg!r}"
    else:
        raise AssertionError("expected NoSuchEntity detaching an already-detached policy, got success")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
