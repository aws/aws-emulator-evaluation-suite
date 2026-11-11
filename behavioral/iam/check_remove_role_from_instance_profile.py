"""remove-role-from-instance-profile."""
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

CHECK = "remove-role-from-instance-profile"
GROUP = 'instance_profiles'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveRoleFromInstanceProfile -> GetInstanceProfile shows empty roles;
    repeating the removal on the now-detached role raises NoSuchEntity."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY,
        Path="/",
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    profile = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(
        InstanceProfileName=profile,
        Path="/",
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=profile: iam.delete_instance_profile(InstanceProfileName=n))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role)
    iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=role)
    resp = iam.get_instance_profile(InstanceProfileName=profile)
    roles = resp["InstanceProfile"]["Roles"]
    assert roles == [], f"expected no roles on {profile} after remove, got {roles!r}"

    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=role)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "NoSuchEntity", f"expected NoSuchEntity on repeat remove, got {code}"
        message = err.response["Error"].get("Message")
        expected = f"Role {role} in Instance Profile {profile} cannot be found."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("repeat RemoveRoleFromInstanceProfile on a detached role unexpectedly succeeded")
    still_empty = iam.get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]["Roles"]
    assert still_empty == [], f"expected no roles on {profile} after failed repeat remove, got {still_empty!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
