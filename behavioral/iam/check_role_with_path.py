"""role-with-path."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "role-with-path"
GROUP = 'path_handling'
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
    """CreateRole with Path includes path in ARN and GetRole response."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    path = "/sim2real/testing/"
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path=path,
        Tags=[{"Key": "sim2real-check", "Value": "role-with-path"}],
    )
    ctx.on_cleanup(lambda n=name: iam.delete_role(RoleName=n))
    role = iam.get_role(RoleName=name)["Role"]
    assert role["Path"] == path, f"expected Path {path!r}, got {role['Path']!r}"
    expected_arn_fragment = f":role{path}{name}"
    assert expected_arn_fragment in role["Arn"], (
        f"expected {expected_arn_fragment!r} in Arn, got {role['Arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
