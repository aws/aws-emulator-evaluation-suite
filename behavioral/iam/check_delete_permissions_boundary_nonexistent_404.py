"""delete-permissions-boundary-nonexistent-404."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-permissions-boundary-nonexistent-404"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRolePermissionsBoundary and DeleteUserPermissionsBoundary both return
    NoSuchEntityException (404) when no permissions boundary is currently set,
    and the same call succeeds once a boundary has actually been attached."""
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-boundary-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_id = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))[
        "Role"
    ]["RoleId"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    user_name = ctx.unique_name("sim2real-boundary-user-")
    user_id = iam.create_user(UserName=user_name)["User"]["UserId"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # Negative: neither entity has ever had a boundary attached.
    expected_role = f"Principal {role_id} does not have scope"
    expected_user = f"Principal {user_id} does not have scope"
    code_role, message_role = _error(lambda: iam.delete_role_permissions_boundary(RoleName=role_name))
    assert code_role == "NoSuchEntity", f"expected NoSuchEntity for role, got {code_role!r}"
    assert message_role == expected_role, f"expected message {expected_role!r}, got {message_role!r}"
    code_user, message_user = _error(lambda: iam.delete_user_permissions_boundary(UserName=user_name))
    assert code_user == "NoSuchEntity", f"expected NoSuchEntity for user, got {code_user!r}"
    assert message_user == expected_user, f"expected message {expected_user!r}, got {message_user!r}"

    boundary_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    # Positive control: attach a boundary, then delete succeeds and clears it.
    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=boundary_arn)
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"] == boundary_arn, (
        f"expected boundary {boundary_arn!r} on role after Put, got {role.get('PermissionsBoundary')!r}"
    )
    iam.delete_role_permissions_boundary(RoleName=role_name)
    role_after = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in role_after, (
        f"expected no boundary on role after delete, got {role_after.get('PermissionsBoundary')!r}"
    )

    iam.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=boundary_arn)
    user = iam.get_user(UserName=user_name)["User"]
    assert user["PermissionsBoundary"]["PermissionsBoundaryArn"] == boundary_arn, (
        f"expected boundary {boundary_arn!r} on user after Put, got {user.get('PermissionsBoundary')!r}"
    )
    iam.delete_user_permissions_boundary(UserName=user_name)
    user_after = iam.get_user(UserName=user_name)["User"]
    assert "PermissionsBoundary" not in user_after, (
        f"expected no boundary on user after delete, got {user_after.get('PermissionsBoundary')!r}"
    )

    # Calling delete again now that it's gone reproduces the same 404, and an
    # independent read confirms the second call did not somehow leave state changed.
    code_role_again, message_role_again = _error(
        lambda: iam.delete_role_permissions_boundary(RoleName=role_name)
    )
    assert code_role_again == "NoSuchEntity", f"expected NoSuchEntity for role, got {code_role_again!r}"
    assert message_role_again == expected_role, (
        f"expected message {expected_role!r}, got {message_role_again!r}"
    )
    role_final = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in role_final, (
        f"expected no boundary on role after repeated delete, got {role_final.get('PermissionsBoundary')!r}"
    )

    code_user_again, message_user_again = _error(
        lambda: iam.delete_user_permissions_boundary(UserName=user_name)
    )
    assert code_user_again == "NoSuchEntity", f"expected NoSuchEntity for user, got {code_user_again!r}"
    assert message_user_again == expected_user, (
        f"expected message {expected_user!r}, got {message_user_again!r}"
    )
    user_final = iam.get_user(UserName=user_name)["User"]
    assert "PermissionsBoundary" not in user_final, (
        f"expected no boundary on user after repeated delete, got {user_final.get('PermissionsBoundary')!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
