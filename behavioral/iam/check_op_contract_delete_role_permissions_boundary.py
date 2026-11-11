"""op-contract-deleteRolePermissionsBoundary."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-deleteRolePermissionsBoundary"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRolePermissionsBoundary clears a role's boundary; on a role without one it
    fails with NoSuchEntity and the exact "does not have scope" message, and a new
    Put/Delete cycle still works."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-boundrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))

    boundary_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    iam.put_role_permissions_boundary(RoleName=role, PermissionsBoundary=boundary_arn)
    fetched = iam.get_role(RoleName=role)["Role"]
    assert fetched["PermissionsBoundary"]["PermissionsBoundaryArn"] == boundary_arn, (
        f"expected boundary {boundary_arn} after Put, got {fetched.get('PermissionsBoundary')!r}"
    )

    iam.delete_role_permissions_boundary(RoleName=role)
    fetched_after = iam.get_role(RoleName=role)["Role"]
    assert "PermissionsBoundary" not in fetched_after, (
        f"expected boundary cleared after Delete, got {fetched_after.get('PermissionsBoundary')!r}"
    )

    # Distinct error boundary: role exists but has no boundary set anymore ->
    # NoSuchEntityException on a second delete.
    code, code_msg = _client_error(lambda: iam.delete_role_permissions_boundary(RoleName=role))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for delete with no boundary set, got {code!r}"
    assert code_msg == f"Principal {fetched_after['RoleId']} does not have scope", f"unexpected error message {code_msg!r}"
    fetched_still_absent = iam.get_role(RoleName=role)["Role"]
    assert "PermissionsBoundary" not in fetched_still_absent, (
        f"rejected delete must not change state, got {fetched_still_absent.get('PermissionsBoundary')!r}"
    )

    # Reusability: the rejected delete must not have bricked the role's boundary slot -
    # the identical Put/Delete cycle succeeds again on the same role.
    iam.put_role_permissions_boundary(RoleName=role, PermissionsBoundary=boundary_arn)
    refetched = iam.get_role(RoleName=role)["Role"]
    assert refetched["PermissionsBoundary"]["PermissionsBoundaryArn"] == boundary_arn, (
        f"expected boundary re-attachable as {boundary_arn}, got {refetched.get('PermissionsBoundary')!r}"
    )
    iam.delete_role_permissions_boundary(RoleName=role)
    final = iam.get_role(RoleName=role)["Role"]
    assert "PermissionsBoundary" not in final, (
        f"expected boundary cleared on the repeat cycle, got {final.get('PermissionsBoundary')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
