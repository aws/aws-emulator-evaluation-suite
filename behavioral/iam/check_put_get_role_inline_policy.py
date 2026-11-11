"""put-get-role-inline-policy."""
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

CHECK = "put-get-role-inline-policy"
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
    """PutRolePolicy -> GetRolePolicy returns the document."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    pol_name = "sim2real-behav-inline-test"
    iam.put_role_policy(RoleName=role, PolicyName=pol_name, PolicyDocument=MINIMAL_POLICY_DOCUMENT)
    ctx.on_cleanup(lambda r=role, n=pol_name: iam.delete_role_policy(RoleName=r, PolicyName=n))
    resp = iam.get_role_policy(RoleName=role, PolicyName=pol_name)
    assert resp["RoleName"] == role, f"expected RoleName {role!r}, got {resp['RoleName']!r}"
    assert resp["PolicyName"] == pol_name, f"expected PolicyName {pol_name!r}, got {resp['PolicyName']!r}"
    doc = resp["PolicyDocument"]
    if isinstance(doc, str):
        from urllib.parse import unquote

        doc = json.loads(unquote(doc))
    stmt = doc["Statement"][0]
    assert stmt["Effect"] == "Allow", f"expected Effect 'Allow', got {stmt.get('Effect')!r}"
    assert stmt["Action"] == "iam:GetUser", f"expected Action 'iam:GetUser', got {stmt.get('Action')!r}"
    assert stmt["Resource"] == "arn:aws:iam::*:user/sim2real-behav-*", (
        f"expected Resource 'arn:aws:iam::*:user/sim2real-behav-*', got {stmt.get('Resource')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
