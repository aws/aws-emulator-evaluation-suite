"""detach-not-attached-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

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

CHECK = "detach-not-attached-policy"
GROUP = 'errors'
SERVICES = ['iam']

ERR_NO_SUCH_ENTITY = "NoSuchEntity"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetachRolePolicy succeeds for an attached policy (positive control); the identical
    call for a policy that was never attached to the role raises NoSuchEntity."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    attached_arn = iam.create_policy(PolicyName=ctx.unique_name("sim2real-behav-pol-attached-"), PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=attached_arn: iam.delete_policy(PolicyArn=a))
    unattached_arn = iam.create_policy(PolicyName=ctx.unique_name("sim2real-behav-pol-unattached-"), PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=unattached_arn: iam.delete_policy(PolicyArn=a))

    # positive control: DetachRolePolicy succeeds for a policy that is genuinely attached
    iam.attach_role_policy(RoleName=role, PolicyArn=attached_arn)
    iam.detach_role_policy(RoleName=role, PolicyArn=attached_arn)
    still_attached = [p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]]
    assert attached_arn not in still_attached, f"expected {attached_arn} detached, still attached: {still_attached}"

    # negative: the identical call for a policy never attached to this role is rejected
    try:
        iam.detach_role_policy(RoleName=role, PolicyArn=unattached_arn)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_NO_SUCH_ENTITY, f"Expected {ERR_NO_SUCH_ENTITY}, got {code!r}"
    assert message == f"Policy {unattached_arn} was not found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
