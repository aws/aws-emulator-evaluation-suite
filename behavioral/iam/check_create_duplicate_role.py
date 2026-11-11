"""create-duplicate-role."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

CHECK = "create-duplicate-role"
GROUP = 'errors'
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

CONFLICTING_TRUST_POLICY = json.dumps(
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

TAGS = [{"Key": "env", "Value": "sim2real"}, {"Key": "purpose", "Value": "behavioral-test"}]

ERR_ENTITY_ALREADY_EXISTS = "EntityAlreadyExists"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a role with an existing name raises EntityAlreadyExists, leaves the
    original role's own trust policy untouched, and the name becomes creatable again
    once the original is deleted."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    live = {"exists": False}

    def _cleanup():
        if live["exists"]:
            iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)

    iam.create_role(RoleName=name, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/", Tags=TAGS)
    live["exists"] = True

    try:
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=CONFLICTING_TRUST_POLICY)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_ENTITY_ALREADY_EXISTS, (
        f"expected duplicate CreateRole to raise {ERR_ENTITY_ALREADY_EXISTS!r}, got {code!r}"
    )
    assert message == f"Role with name {name} already exists.", (
        f"expected the exact EntityAlreadyExists message AWS returns, got {message!r}"
    )

    # Independent read at the destination: the rejected duplicate (with a DIFFERENT
    # trust policy) must not have mutated the original role.
    unaffected = iam.get_role(RoleName=name)["Role"]["AssumeRolePolicyDocument"]
    assert unaffected == json.loads(MINIMAL_TRUST_POLICY), (
        f"rejected duplicate CreateRole must leave the original trust policy untouched, "
        f"expected {json.loads(MINIMAL_TRUST_POLICY)!r}, got {unaffected!r}"
    )

    # Restore: freeing the name by deleting the original must let the identical call
    # succeed again, proving the rejection was about the name, not a permanent block.
    iam.delete_role(RoleName=name)
    live["exists"] = False
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/", Tags=TAGS)
    live["exists"] = True

    recreated = iam.get_role(RoleName=name)["Role"]
    assert recreated["RoleName"] == name, (
        f"freed name must be creatable again, expected role {name!r} to exist, got {recreated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
