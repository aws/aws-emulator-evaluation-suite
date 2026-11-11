"""op-contract-deleteInstanceProfile."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteInstanceProfile"
GROUP = "error-semantics"
SERVICES = ["iam"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteInstanceProfile removes an empty profile; DeleteConflict while a role is attached."""
    import json

    iam = ctx.client("iam")

    # success path
    profile_name = ctx.unique_name("sim2real-behav-ip-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    assert profile_name in [
        p["InstanceProfileName"] for p in _listed(iam, "list_instance_profiles", "InstanceProfiles")
    ], "created instance profile not found in ListInstanceProfiles"
    resp = iam.delete_instance_profile(InstanceProfileName=profile_name)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from DeleteInstanceProfile, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    # substantive state check: the profile is actually gone from the account's profile list,
    # not merely that the call returned 200
    remaining_names = [p["InstanceProfileName"] for p in _listed(iam, "list_instance_profiles", "InstanceProfiles")]
    assert profile_name not in remaining_names, "deleted instance profile still present in ListInstanceProfiles"
    code, message = _error(lambda: iam.get_instance_profile(InstanceProfileName=profile_name))
    assert code == "NoSuchEntity", f"expected profile gone, got {code}"
    expected = f"Instance Profile {profile_name} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # error boundary: profile with a role attached cannot be deleted
    conflict_profile = ctx.unique_name("sim2real-behav-ip-conflict-")
    role_name = ctx.unique_name("sim2real-behav-role-for-ip-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY))
    iam.create_instance_profile(InstanceProfileName=conflict_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=conflict_profile, RoleName=role_name)

    def _cleanup():
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=conflict_profile, RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_instance_profile(InstanceProfileName=conflict_profile)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)

    conflict_code, conflict_message = _error(
        lambda: iam.delete_instance_profile(InstanceProfileName=conflict_profile)
    )
    assert conflict_code == "DeleteConflict", f"expected DeleteConflict, got {conflict_code}"
    expected_conflict = "Cannot delete entity, must remove roles from instance profile first."
    assert conflict_message == expected_conflict, (
        f"expected message {expected_conflict!r}, got {conflict_message!r}"
    )

    # effect absent: the rejected delete must not have removed the profile
    still_present = iam.get_instance_profile(InstanceProfileName=conflict_profile)["InstanceProfile"]
    assert still_present["InstanceProfileName"] == conflict_profile, (
        "instance profile must survive a DeleteConflict-rejected delete"
    )

    # restore: detach the role, then the identical delete call must succeed
    iam.remove_role_from_instance_profile(InstanceProfileName=conflict_profile, RoleName=role_name)
    iam.delete_instance_profile(InstanceProfileName=conflict_profile)
    post_delete_code, post_delete_message = _error(
        lambda: iam.get_instance_profile(InstanceProfileName=conflict_profile)
    )
    assert post_delete_code == "NoSuchEntity", (
        f"expected profile gone after role detached and delete retried, got {post_delete_code}"
    )
    expected_gone = f"Instance Profile {conflict_profile} cannot be found."
    assert post_delete_message == expected_gone, (
        f"expected message {expected_gone!r}, got {post_delete_message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _listed(iam, operation, key):
    """Every item an IAM listing returns, across all pages."""
    return [item for page in iam.get_paginator(operation).paginate() for item in page[key]]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
