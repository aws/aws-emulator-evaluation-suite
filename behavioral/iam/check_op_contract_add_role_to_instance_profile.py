"""op-contract-add-role-to-instance-profile."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-add-role-to-instance-profile"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An instance profile holds one role: AddRoleToInstanceProfile with a second role fails
    with LimitExceeded and its exact message leaving the first, and succeeds once the first is
    removed."""
    iam = ctx.client("iam")

    profile_name = ctx.unique_name("sim2real-ip-")
    iam.create_instance_profile(
        InstanceProfileName=profile_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))

    role1 = _create_role(ctx, iam)
    role2 = _create_role(ctx, iam)

    # positive control: role1 attaches and is visible on an independent read
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role1)
    role1_attached = {"value": True}

    def _cleanup_role1() -> None:
        if role1_attached["value"]:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role1)

    ctx.on_cleanup(_cleanup_role1)

    profile = _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"],
        lambda p: any(r["RoleName"] == role1 for r in p["Roles"]),
    )
    role_names = [r["RoleName"] for r in profile["Roles"]]
    assert role_names == [role1], f"expected only {role1!r} attached, got {role_names!r}"

    # break: the slot is occupied, so the second role must be rejected
    code, message = _error(
        lambda: iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role2)
    )
    assert code == "LimitExceeded", f"expected LimitExceeded (max 1 role/instance-profile), got {code}"
    expected = "Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected role never appears, via an independent read
    rejected_profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    rejected_role_names = [r["RoleName"] for r in rejected_profile["Roles"]]
    assert rejected_role_names == [role1], (
        f"rejected AddRoleToInstanceProfile must not add {role2!r}, got {rejected_role_names!r}"
    )

    # restore: free the slot, then the identical call succeeds
    iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role1)
    role1_attached["value"] = False
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role2)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role2)
    )

    restored_profile = _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"],
        lambda p: any(r["RoleName"] == role2 for r in p["Roles"]),
    )
    restored_role_names = [r["RoleName"] for r in restored_profile["Roles"]]
    assert restored_role_names == [role2], (
        f"freeing the slot must let {role2!r} attach, got {restored_role_names!r}"
    )


def _create_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-role-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name


def _poll_until(probe, predicate, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
