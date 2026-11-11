"""put-user-permissions-boundary-non-attachable-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-user-permissions-boundary-non-attachable-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]

READONLY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutUserPermissionsBoundary rejects the same class of non-attachable AWS managed
    policy ARNs with PolicyNotAttachableException, leaves the user unmodified, while an
    attachable policy ARN (positive control) succeeds and is reflected on GetUser."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(
        UserName=user_name,
        Tags=[{"Key": "sim2real", "Value": "put-user-permissions-boundary-non-attachable-rejected"}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    non_attachable_arn = _find_non_attachable_aws_policy_arn(ctx)
    if non_attachable_arn is None:
        raise AssertionError("no non-attachable AWS managed policy discoverable in this partition")

    user_before = iam.get_user(UserName=user_name)["User"]
    assert "PermissionsBoundary" not in user_before, (
        f"expected no PermissionsBoundary on a fresh user, got {user_before.get('PermissionsBoundary')!r}"
    )

    code, message = _error_code(
        lambda: iam.put_user_permissions_boundary(
            UserName=user_name, PermissionsBoundary=non_attachable_arn
        )
    )
    assert code == "PolicyNotAttachable", f"expected PolicyNotAttachable, got {code!r}"
    assert message == "Cannot attach AWS reserved policy to an IAM user.", message

    user_after_reject = iam.get_user(UserName=user_name)["User"]
    assert "PermissionsBoundary" not in user_after_reject, (
        f"rejected PutUserPermissionsBoundary must not set a boundary, "
        f"got {user_after_reject.get('PermissionsBoundary')!r}"
    )

    # Positive control: an attachable AWS managed policy is accepted as a boundary.
    iam.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=READONLY_ARN)
    ctx.on_cleanup(lambda: iam.delete_user_permissions_boundary(UserName=user_name))
    user_with_boundary = iam.get_user(UserName=user_name)["User"]
    actual_boundary_arn = user_with_boundary["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_boundary_arn == READONLY_ARN, (
        f"expected the attachable positive-control policy {READONLY_ARN!r} reflected as the "
        f"user's boundary on an independent GetUser, got {actual_boundary_arn!r}"
    )


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected PolicyNotAttachable, but the call SUCCEEDED and returned {result!r}"
    )


def _find_non_attachable_aws_policy_arn(ctx):
    """Locate an AWS-managed policy that PutUserPermissionsBoundary rejects with
    PolicyNotAttachable: the internal policies reserved for service-linked roles, which live
    exclusively under the reserved "/aws-service-role/" path.

    Does NOT filter on IsAttachable: ListPolicies' IsAttachable field does not reliably report
    False for these policies, so a filter on that field can come up empty. The path reservation is
    the durable signal — every policy under /aws-service-role/ is rejected by
    Put*PermissionsBoundary with PolicyNotAttachable regardless of what IsAttachable reports."""
    iam = ctx.client("iam")
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="AWS", PathPrefix="/aws-service-role/", MaxItems=200):
        policies = page.get("Policies", [])
        if policies:
            return policies[0]["Arn"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
