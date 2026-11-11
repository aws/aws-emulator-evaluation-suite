"""instance-profile-single-role-constraint."""
from __future__ import annotations

from botocore.exceptions import ClientError

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

CHECK = "instance-profile-single-role-constraint"
GROUP = 'instance_profiles'
SERVICES = ['iam']

ERR_LIMIT_EXCEEDED = "LimitExceeded"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Adding a second role to an instance profile raises LimitExceeded, the rejected
    role never lands, and freeing the one slot lets a different role take it.

    AWS enforces a limit of exactly one role per instance profile.
    """
    iam = ctx.client("iam")
    role1 = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role1, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role1: iam.delete_role(RoleName=n))
    role2 = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role2, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role2: iam.delete_role(RoleName=n))
    profile = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(InstanceProfileName=profile, Path="/")
    ctx.on_cleanup(lambda n=profile: iam.delete_instance_profile(InstanceProfileName=n))

    # Positive control: the profile accepts its first role.
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role1)

    # Break: a second role is rejected with the specific quota error.
    try:
        iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role2)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_LIMIT_EXCEEDED, f"Expected {ERR_LIMIT_EXCEEDED}, got {code!r}"
    assert message == "Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1", (
        f"expected the exact LimitExceeded message AWS returns, got {message!r}"
    )

    # Effect-absent: an independent read shows the rejected role never landed.
    roles_after_reject = iam.get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]["Roles"]
    assert [r["RoleName"] for r in roles_after_reject] == [role1], (
        f"rejected AddRoleToInstanceProfile must not have added {role2!r}: {roles_after_reject}"
    )

    # Restore: free the one slot.
    iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=role1)

    # Identical call now succeeds, and an independent read confirms it.
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role2)
    ctx.on_cleanup(lambda ip=profile, r=role2: iam.remove_role_from_instance_profile(InstanceProfileName=ip, RoleName=r))
    roles_after_restore = iam.get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]["Roles"]
    assert [r["RoleName"] for r in roles_after_restore] == [role2], (
        f"freeing the slot must let a different role be added, got {roles_after_restore}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
