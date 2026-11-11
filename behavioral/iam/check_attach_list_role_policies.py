"""attach-list-role-policies."""
from __future__ import annotations

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

CHECK = "attach-list-role-policies"
GROUP = 'attach_detach'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachRolePolicy -> ListAttachedRolePolicies shows the attachment, and
    DetachRolePolicy removes it from that same independent read."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    arn = iam.create_policy(PolicyName=ctx.unique_name("sim2real-behav-pol-"), PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
    iam.attach_role_policy(RoleName=role, PolicyArn=arn)
    ctx.on_cleanup(lambda r=role, p=arn: iam.detach_role_policy(RoleName=r, PolicyArn=p))
    resp = iam.list_attached_role_policies(RoleName=role)
    attached_arns = [p["PolicyArn"] for p in resp["AttachedPolicies"]]
    assert arn in attached_arns, f"expected {arn} in ListAttachedRolePolicies after AttachRolePolicy, got {attached_arns}"

    iam.detach_role_policy(RoleName=role, PolicyArn=arn)
    resp2 = iam.list_attached_role_policies(RoleName=role)
    attached_arns2 = [p["PolicyArn"] for p in resp2["AttachedPolicies"]]
    assert arn not in attached_arns2, f"expected {arn} absent from ListAttachedRolePolicies after DetachRolePolicy, still found in {attached_arns2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
