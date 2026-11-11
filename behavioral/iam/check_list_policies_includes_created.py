"""list-policies-includes-created."""
from __future__ import annotations

import json

from behavioral_harness import tags

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

CHECK = "list-policies-includes-created"
GROUP = 'policy_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPolicies(Scope=Local) includes a policy we just created."""
    iam = ctx.client("iam")
    arn = iam.create_policy(PolicyName=ctx.unique_name("sim2real-behav-pol-"), PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: iam.delete_policy(PolicyArn=a))
    paginator = iam.get_paginator("list_policies")
    found = False
    for page in paginator.paginate(Scope="Local"):
        for pol in page["Policies"]:
            if pol["Arn"] == arn:
                found = True
                break
        if found:
            break
    assert found, f"Policy {arn} not found in ListPolicies"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
