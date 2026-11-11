"""op-contract-list-instance-profiles-for-role."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-instance-profiles-for-role"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInstanceProfilesForRole reflects the role's profile membership; bogus role -> NoSuchEntityException."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_trust_doc())
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    profile_name = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: _remove_role_if_attached(iam, profile_name, role_name))

    resp = iam.list_instance_profiles_for_role(RoleName=role_name)
    names = [p["InstanceProfileName"] for p in resp["InstanceProfiles"]]
    assert profile_name in names, f"{profile_name} missing from ListInstanceProfilesForRole: {names}"
    match = next(p for p in resp["InstanceProfiles"] if p["InstanceProfileName"] == profile_name)
    assert match["Roles"][0]["RoleName"] == role_name, (
        f"expected {role_name} attached to {profile_name}, got {match['Roles']}"
    )

    iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    resp_after = iam.list_instance_profiles_for_role(RoleName=role_name)
    names_after = [p["InstanceProfileName"] for p in resp_after["InstanceProfiles"]]
    assert profile_name not in names_after, (
        f"{profile_name} still in ListInstanceProfilesForRole after remove_role_from_instance_profile: {names_after}"
    )

    missing_role = ctx.unique_name("sim2real-nonexistent-")
    code, message = _error(lambda: iam.list_instance_profiles_for_role(RoleName=missing_role))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The role with name {missing_role} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _trust_doc() -> str:
    return json.dumps(
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


def _remove_role_if_attached(iam, profile_name, role_name):
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
