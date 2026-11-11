"""role-arn-format."""
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

CHECK = "role-arn-format"
GROUP = 'role_lifecycle'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Role ARN follows the format arn:aws:iam::<account>:role/<path><name>."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=name: iam.delete_role(RoleName=n))
    role = iam.get_role(RoleName=name)["Role"]
    arn = role["Arn"]
    assert arn.endswith(f":role/{name}"), f"ARN {arn} does not end with :role/{name}"
    parts = arn.split(":")
    assert parts[0] == "arn", f"expected ARN prefix 'arn', got {parts[0]!r} in {arn!r}"
    assert parts[1] == "aws", f"expected partition 'aws', got {parts[1]!r} in {arn!r}"
    assert parts[2] == "iam", f"expected service 'iam', got {parts[2]!r} in {arn!r}"
    assert parts[3] == "", f"IAM is global so the ARN region field must be empty, got {parts[3]!r} in {arn!r}"
    assert parts[4] == account, (
        f"ARN account field must equal the caller account {account!r}, got {parts[4]!r} in {arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
