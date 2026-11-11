"""list-role-inline-policies."""
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

CHECK = "list-role-inline-policies"
GROUP = 'inline_policies'
SERVICES = ['iam']

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRolePolicies returns exactly the inline policy names put on the role, not truncated."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    pol_name = "sim2real-behav-inline-list"
    iam.put_role_policy(RoleName=role, PolicyName=pol_name, PolicyDocument=MINIMAL_POLICY_DOCUMENT)
    ctx.on_cleanup(lambda r=role, n=pol_name: iam.delete_role_policy(RoleName=r, PolicyName=n))
    resp = iam.list_role_policies(RoleName=role)
    assert resp["PolicyNames"] == [pol_name], f"expected exactly [{pol_name}], got {resp['PolicyNames']}"
    assert resp["IsTruncated"] is False, f"expected IsTruncated False, got {resp['IsTruncated']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
