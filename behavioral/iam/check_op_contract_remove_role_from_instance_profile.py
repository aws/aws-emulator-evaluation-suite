"""op-contract-remove-role-from-instance-profile."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-remove-role-from-instance-profile"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveRoleFromInstanceProfile detaches the role so GetInstanceProfile.Roles
    becomes empty; calling it again for a role no longer attached raises NoSuchEntity."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    profile_name = ctx.unique_name("sim2real-behav-profile-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "op-contract-remove-role-from-instance-profile"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.create_instance_profile(
        InstanceProfileName=profile_name,
        Tags=[{"Key": "sim2real", "Value": "op-contract-remove-role-from-instance-profile"}],
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    _wait_role_visible(ctx, role_name)

    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    attached = iam.get_instance_profile(InstanceProfileName=profile_name)
    attached_roles = [r["RoleName"] for r in attached["InstanceProfile"]["Roles"]]
    assert attached_roles == [role_name], f"expected [{role_name}], got {attached_roles}"

    iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    detached = iam.get_instance_profile(InstanceProfileName=profile_name)
    detached_roles = detached["InstanceProfile"]["Roles"]
    assert detached_roles == [], f"expected no roles after detach, got {detached_roles}"

    # error boundary: role is no longer attached to this profile
    code, message = _error(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=profile_name, RoleName=role_name
    ))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"Role {role_name} in Instance Profile {profile_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # confirm profile state is unaffected by the failed retry
    still_empty = iam.get_instance_profile(InstanceProfileName=profile_name)
    assert still_empty["InstanceProfile"]["Roles"] == [], (
        f"expected no roles after rejected retry, got {still_empty['InstanceProfile']['Roles']}"
    )

    # the identifier remains usable: re-attaching after the rejected retry succeeds
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    reattached = iam.get_instance_profile(InstanceProfileName=profile_name)
    reattached_roles = [r["RoleName"] for r in reattached["InstanceProfile"]["Roles"]]
    assert reattached_roles == [role_name], f"expected [{role_name}] after reattach, got {reattached_roles}"

    # restore the detached state: both DeleteRole and DeleteInstanceProfile refuse while a role
    # is still attached, and cleanup deletes both independently
    iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    final = iam.get_instance_profile(InstanceProfileName=profile_name)
    assert final["InstanceProfile"]["Roles"] == [], (
        f"expected no roles before teardown, got {final['InstanceProfile']['Roles']}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_role_visible(ctx, role_name, timeout_s=15.0, interval_s=1.0):
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(interval_s)
    raise AssertionError(f"role {role_name} never became visible")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
