"""untag-role."""
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

CHECK = "untag-role"
GROUP = 'tags'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagRole removes a specific tag key."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    iam.tag_role(
        RoleName=role,
        Tags=[
            {"Key": "keep", "Value": "yes"},
            {"Key": "remove", "Value": "no"},
        ],
    )
    iam.untag_role(RoleName=role, TagKeys=["remove"])
    resp = iam.list_role_tags(RoleName=role)
    remaining = {t["Key"]: t["Value"] for t in resp["Tags"]}
    assert remaining == {"keep": "yes"}, f"expected only the untouched tag to survive, got {remaining}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
