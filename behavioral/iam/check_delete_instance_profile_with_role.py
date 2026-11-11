"""delete-instance-profile-with-role."""
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

CHECK = "delete-instance-profile-with-role"
GROUP = 'instance_profiles'
SERVICES = ['iam']

ERR_DELETE_CONFLICT = "DeleteConflict"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"


def _err_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


def _unless_gone(fn):
    """Teardown: the body deletes this resource itself, so NoSuchEntity is fine; anything else raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteInstanceProfile with a role attached fails DeleteConflict and the profile survives;
    once the role is removed the same delete succeeds. A role-free control profile deletes cleanly."""
    iam = ctx.client("iam")

    control_profile = ctx.unique_name("sim2real-behav-ip-ctrl-")
    iam.create_instance_profile(InstanceProfileName=control_profile, Path="/")
    iam.delete_instance_profile(InstanceProfileName=control_profile)
    control_code, control_message = _err_code(lambda: iam.get_instance_profile(InstanceProfileName=control_profile))
    assert control_code == ERR_NO_SUCH_ENTITY, (
        f"positive control: expected {ERR_NO_SUCH_ENTITY} after a role-free delete, got {control_code!r}"
    )
    assert control_message == f"Instance Profile {control_profile} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {control_message!r}"
    )

    role = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path="/")
    ctx.on_cleanup(lambda n=role: iam.delete_role(RoleName=n))
    profile = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(InstanceProfileName=profile, Path="/")
    ctx.on_cleanup(lambda n=profile: _unless_gone(lambda: iam.delete_instance_profile(InstanceProfileName=n)))
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role)
    ctx.on_cleanup(
        lambda ip=profile, r=role: _unless_gone(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ip, RoleName=r)
        )
    )

    try:
        iam.delete_instance_profile(InstanceProfileName=profile)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_DELETE_CONFLICT, f"Expected {ERR_DELETE_CONFLICT}, got {code!r}"
    assert message == "Cannot delete entity, must remove roles from instance profile first.", (
        f"expected the exact DeleteConflict message AWS returns, got {message!r}"
    )

    survived = iam.get_instance_profile(InstanceProfileName=profile)
    assert survived["InstanceProfile"]["InstanceProfileName"] == profile, (
        "instance profile should survive a DeleteConflict"
    )

    iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=role)
    iam.delete_instance_profile(InstanceProfileName=profile)

    gone_code, gone_message = _err_code(lambda: iam.get_instance_profile(InstanceProfileName=profile))
    assert gone_code == ERR_NO_SUCH_ENTITY, (
        f"instance profile should be gone once its role is removed, got {gone_code!r}"
    )
    assert gone_message == f"Instance Profile {profile} cannot be found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
