"""put-role-permissions-boundary-non-attachable-rejected."""

from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-role-permissions-boundary-non-attachable-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

READONLY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """PutRolePermissionsBoundary rejects a non-attachable AWS managed policy ARN with
    PolicyNotAttachableException and leaves the role's boundary untouched, while an
    attachable policy ARN (positive control) succeeds and is reflected on GetRole."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json(TRUST_POLICY),
        Tags=[
            {
                "Key": "sim2real",
                "Value": "put-role-permissions-boundary-non-attachable-rejected",
            }
        ],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    non_attachable_arn = _find_non_attachable_aws_policy_arn(ctx)
    if non_attachable_arn is None:
        raise AssertionError(
            "no non-attachable AWS managed policy discoverable in this partition"
        )

    # Baseline: role has no permissions boundary yet.
    role_before = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in role_before, (
        f"expected no PermissionsBoundary on a fresh role, got {role_before.get('PermissionsBoundary')!r}"
    )

    code, message = _error_code(
        lambda: iam.put_role_permissions_boundary(
            RoleName=role_name, PermissionsBoundary=non_attachable_arn
        )
    )
    assert code == "PolicyNotAttachable", f"expected PolicyNotAttachable, got {code!r}"
    assert message == "Cannot attach AWS reserved policy to an IAM role.", message

    # The rejected call must not have mutated the role.
    role_after_reject = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in role_after_reject, (
        f"rejected PutRolePermissionsBoundary must not set a boundary, "
        f"got {role_after_reject.get('PermissionsBoundary')!r}"
    )

    # Positive control: an attachable AWS managed policy is accepted as a boundary.
    iam.put_role_permissions_boundary(
        RoleName=role_name, PermissionsBoundary=READONLY_ARN
    )
    ctx.on_cleanup(lambda: iam.delete_role_permissions_boundary(RoleName=role_name))
    role_with_boundary = iam.get_role(RoleName=role_name)["Role"]
    actual_boundary_arn = role_with_boundary["PermissionsBoundary"][
        "PermissionsBoundaryArn"
    ]
    assert actual_boundary_arn == READONLY_ARN, (
        f"expected the attachable positive-control policy {READONLY_ARN!r} reflected as the "
        f"role's boundary on an independent GetRole, got {actual_boundary_arn!r}"
    )


def _json(doc: dict) -> str:
    import json

    return json.dumps(doc)


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
    """Locate an AWS-managed policy that PutRolePermissionsBoundary rejects with
    PolicyNotAttachable: the internal policies reserved for service-linked roles, which live
    exclusively under the reserved "/aws-service-role/" path.

    These policies are rejected with PolicyNotAttachable / "Cannot attach AWS reserved policy to
    an IAM role.". ListPolicies' IsAttachable field does not identify them (it does not report
    False for them), so the policy is selected by path."""
    iam = ctx.client("iam")
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(
        Scope="AWS", PathPrefix="/aws-service-role/", MaxItems=200
    ):
        policies = page.get("Policies", [])
        if policies:
            return policies[0]["Arn"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
