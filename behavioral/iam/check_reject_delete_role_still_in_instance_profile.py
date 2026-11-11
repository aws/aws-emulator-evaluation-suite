"""reject-delete-role-still-in-instance-profile."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-delete-role-still-in-instance-profile"
GROUP = 'overly-permissive'
SERVICES = ['iam']

# A minimal, syntactically valid trust policy for a role whose trust
# relationship semantics this check does not care about.
_DEFAULT_TRUST_POLICY = json.dumps(
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role that is still a member of an instance profile cannot be deleted;
    the role must be removed from the profile first."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-iam-ip-role-")
    profile_name = ctx.unique_name("sim2real-behav-iam-ip-profile-")

    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_DEFAULT_TRUST_POLICY)
    ctx.on_cleanup(lambda: _delete_role_detaching_profiles(iam, role_name))
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _delete_instance_profile(iam, profile_name))
    iam.add_role_to_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    )

    code, message = _error_code(lambda: iam.delete_role(RoleName=role_name))
    assert code == "DeleteConflict", (
        f"expected DeleteConflict for role still in an instance profile, got {code}"
    )
    expected = "Cannot delete entity, must remove roles from instance profile first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The role must still exist and still be attached to the profile.
    assert iam.get_role(RoleName=role_name)["Role"]["RoleName"] == role_name
    got = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    assert [r["RoleName"] for r in got["Roles"]] == [role_name]

    iam.remove_role_from_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    )
    iam.delete_instance_profile(InstanceProfileName=profile_name)
    iam.delete_role(RoleName=role_name)

    # The identical calls that were refused above must now succeed: prove it with an
    # independent read rather than trusting the delete calls not to have raised.
    code_profile_gone, message_profile_gone = _error_code(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name)
    )
    assert code_profile_gone == "NoSuchEntity", (
        f"instance profile should be gone once its role was removed and it was deleted, "
        f"got {code_profile_gone}"
    )
    expected = f"Instance Profile {profile_name} cannot be found."
    assert message_profile_gone == expected, (
        f"expected message {expected!r}, got {message_profile_gone!r}"
    )
    code_role_gone, message_role_gone = _error_code(lambda: iam.get_role(RoleName=role_name))
    assert code_role_gone == "NoSuchEntity", (
        f"role should be gone once removed from the instance profile and deleted, "
        f"got {code_role_gone}"
    )
    expected = f"The role with name {role_name} cannot be found."
    assert message_role_gone == expected, (
        f"expected message {expected!r}, got {message_role_gone!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises,
    because accepting a call real AWS refuses (or still finding a resource that was just deleted) is
    the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_instance_profile(iam, profile_name: str) -> None:
    """An instance profile must be emptied of roles before it can be deleted."""
    try:
        profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return
        raise
    for role in profile.get("Roles", []):
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role["RoleName"]
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_detaching_profiles(iam, role_name: str) -> None:
    """DeleteRole is exactly what this check proves is refused while the role is
    still in an instance profile, so teardown must detach first."""
    try:
        for profile in iam.list_instance_profiles_for_role(RoleName=role_name).get(
            "InstanceProfiles", []
        ):
            try:
                iam.remove_role_from_instance_profile(
                    InstanceProfileName=profile["InstanceProfileName"], RoleName=role_name
                )
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
