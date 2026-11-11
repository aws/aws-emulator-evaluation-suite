"""instance-profile-delete-with-role-conflict-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "instance-profile-delete-with-role-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteInstanceProfile must be rejected with DeleteConflict while a role is still
    associated with the instance profile (state-conflict boundary distinct from the
    role/group attached-policy conflicts covered elsewhere)."""
    iam = ctx.client("iam")
    profile_name = ctx.unique_name("sim2real-behav-instprofile-")
    role_name = ctx.unique_name("sim2real-behav-instprofilerole-")

    # positive control: DeleteInstanceProfile succeeds on a profile with no role attached,
    # so the DeleteConflict asserted below is specific to the role association, not a sign
    # that deletes are refused outright.
    control_profile = ctx.unique_name("sim2real-behav-instprofilectl-")
    iam.create_instance_profile(
        InstanceProfileName=control_profile,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_instance_profile(InstanceProfileName=control_profile)
        )
    )
    iam.delete_instance_profile(InstanceProfileName=control_profile)

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_instance_profile(InstanceProfileName=profile_name)
        )
    )

    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        )
    )

    code, msg = _error(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    assert code == "DeleteConflict", f"expected DeleteConflict, got {code!r}"
    want = "Cannot delete entity, must remove roles from instance profile first."
    assert msg == want, f"DeleteConflict message: wanted {want!r}, got {msg!r}"

    # the instance profile must still exist, still holding the role, after the rejected delete
    got = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    assert any(r["RoleName"] == role_name for r in got["Roles"]), (
        f"expected {role_name!r} still attached to {profile_name!r} after the rejected delete, "
        f"got roles {[r['RoleName'] for r in got['Roles']]!r}"
    )

    # once the conflict is resolved, deletion succeeds normally
    iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    iam.delete_instance_profile(InstanceProfileName=profile_name)
    code_after, msg_after = _error(lambda: iam.get_instance_profile(InstanceProfileName=profile_name))
    assert code_after == "NoSuchEntity", (
        f"expected NoSuchEntity reading {profile_name!r} after the resolved delete, got {code_after!r}"
    )
    want = f"Instance Profile {profile_name} cannot be found."
    assert msg_after == want, f"NoSuchEntity message: wanted {want!r}, got {msg_after!r}"


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
