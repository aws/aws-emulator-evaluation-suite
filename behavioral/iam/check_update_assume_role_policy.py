"""update-assume-role-policy."""
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

CHECK = "update-assume-role-policy"
GROUP = 'trust_policies'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAssumeRolePolicy changes the trust policy document."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    new_trust = json.dumps(
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
    iam.update_assume_role_policy(RoleName=role, PolicyDocument=new_trust)
    role_data = iam.get_role(RoleName=role)["Role"]
    trust = role_data["AssumeRolePolicyDocument"]
    if isinstance(trust, str):
        from urllib.parse import unquote

        trust = json.loads(unquote(trust))
    assert trust["Statement"][0]["Principal"]["Service"] == "ec2.amazonaws.com", (
        f"expected updated trust principal ec2.amazonaws.com, got {trust}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
