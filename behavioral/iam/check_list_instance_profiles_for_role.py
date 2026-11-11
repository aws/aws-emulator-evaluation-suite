"""list-instance-profiles-for-role."""
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

CHECK = "list-instance-profiles-for-role"
GROUP = 'instance_profiles'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInstanceProfilesForRole returns exactly the profiles that contain the role, and drops one once removed."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))

    member = ctx.unique_name("sim2real-behav-ip-member-")
    iam.create_instance_profile(InstanceProfileName=member, Path="/")
    ctx.on_cleanup(lambda n=member: iam.delete_instance_profile(InstanceProfileName=n))

    unrelated = ctx.unique_name("sim2real-behav-ip-unrelated-")
    iam.create_instance_profile(InstanceProfileName=unrelated, Path="/")
    ctx.on_cleanup(lambda n=unrelated: iam.delete_instance_profile(InstanceProfileName=n))

    iam.add_role_to_instance_profile(InstanceProfileName=member, RoleName=role)

    resp = iam.list_instance_profiles_for_role(RoleName=role)
    ip_names = [ip["InstanceProfileName"] for ip in resp["InstanceProfiles"]]
    assert member in ip_names, f"expected {member} in ListInstanceProfilesForRole, got {ip_names}"
    assert unrelated not in ip_names, (
        f"unrelated profile {unrelated} (role never attached) leaked into "
        f"ListInstanceProfilesForRole: {ip_names}"
    )

    iam.remove_role_from_instance_profile(InstanceProfileName=member, RoleName=role)
    resp_after = iam.list_instance_profiles_for_role(RoleName=role)
    ip_names_after = [ip["InstanceProfileName"] for ip in resp_after["InstanceProfiles"]]
    assert member not in ip_names_after, (
        f"{member} still in ListInstanceProfilesForRole after RemoveRoleFromInstanceProfile: "
        f"{ip_names_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
