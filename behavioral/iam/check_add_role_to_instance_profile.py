"""add-role-to-instance-profile."""
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

CHECK = "add-role-to-instance-profile"
GROUP = 'instance_profiles'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddRoleToInstanceProfile -> GetInstanceProfile shows the role."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    profile = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(InstanceProfileName=profile, Path="/")
    ctx.on_cleanup(lambda n=profile: iam.delete_instance_profile(InstanceProfileName=n))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role)
    ctx.on_cleanup(lambda ip=profile, r=role: iam.remove_role_from_instance_profile(InstanceProfileName=ip, RoleName=r))
    resp = iam.get_instance_profile(InstanceProfileName=profile)
    role_names = [r["RoleName"] for r in resp["InstanceProfile"]["Roles"]]
    assert role in role_names, f"expected {role!r} in instance profile roles, got {role_names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
