"""create-role-with-description."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-role-with-description"
GROUP = 'role_lifecycle'
SERVICES = ['iam']

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRole with Description; GetRole returns it."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Description="sim2real test role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=name: iam.delete_role(RoleName=n))
    role = iam.get_role(RoleName=name)["Role"]
    assert role.get("Description") == "sim2real test role", (
        f"expected Description to round-trip on GetRole, got {role.get('Description')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
