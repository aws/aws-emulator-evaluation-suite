"""update-role-description-and-metadata."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-role-description-and-metadata"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Role description and session-duration updates persist and are reflected on GetRole."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-updaterole-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="initial description",
        MaxSessionDuration=3600,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    got = iam.get_role(RoleName=role_name)["Role"]
    assert got["Description"] == "initial description", got
    assert got["MaxSessionDuration"] == 3600, got

    iam.update_role_description(RoleName=role_name, Description="updated via UpdateRoleDescription")
    got = iam.get_role(RoleName=role_name)["Role"]
    assert got["Description"] == "updated via UpdateRoleDescription", got
    # UpdateRoleDescription only names the description in its request; it must not clobber the
    # session duration that CreateRole set.
    assert got["MaxSessionDuration"] == 3600, got

    iam.update_role(
        RoleName=role_name, MaxSessionDuration=7200, Description="updated via UpdateRole"
    )
    got = iam.get_role(RoleName=role_name)["Role"]
    assert got["Description"] == "updated via UpdateRole", got
    assert got["MaxSessionDuration"] == 7200, got


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
