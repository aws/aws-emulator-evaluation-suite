"""permissions-boundary-non-attachable-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "permissions-boundary-non-attachable-policy-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_TRUST_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)
_VALID_BOUNDARY_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRolePermissionsBoundary rejects a non-attachable AWS managed policy (e.g. one scoped to
    a service-linked role) with PolicyNotAttachable and leaves the role without a boundary; the
    same call with an ordinary attachable managed policy succeeds (positive control)."""
    iam = ctx.client("iam")
    non_attachable_arn = _find_non_attachable_aws_policy(iam)
    if non_attachable_arn is None:
        raise AssertionError("no non-attachable AWS managed policy discoverable in this partition")

    role_name = ctx.unique_name("sim2real-behav-rboundary-neg-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_DOC,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    code, message = _error_code(
        lambda: iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=non_attachable_arn)
    )
    assert code == "PolicyNotAttachable", f"expected PolicyNotAttachable, got {code!r}"
    assert message == "Cannot attach AWS reserved policy to an IAM role.", message

    role = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in role, "rejected boundary must not have been applied"

    # Positive control: an attachable managed policy is accepted as a boundary on the same role.
    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=_VALID_BOUNDARY_ARN)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_permissions_boundary(RoleName=role_name)))
    role_after = iam.get_role(RoleName=role_name)["Role"]
    actual_boundary_arn = role_after["PermissionsBoundary"]["PermissionsBoundaryArn"]
    assert actual_boundary_arn == _VALID_BOUNDARY_ARN, (
        f"expected the attachable positive-control policy {_VALID_BOUNDARY_ARN!r} reflected as "
        f"the role's boundary on an independent GetRole, got {actual_boundary_arn!r}"
    )


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected PolicyNotAttachable, but the call SUCCEEDED and returned {result!r}")


def _find_non_attachable_aws_policy(iam):
    """Locate an AWS-managed policy that PutRolePermissionsBoundary rejects with
    PolicyNotAttachable: the internal policies reserved for service-linked roles, which live
    exclusively under the reserved "/aws-service-role/" path. ListPolicies' own IsAttachable field
    no longer reports False for any AWS-managed policy in this partition, so filtering on it always
    comes up empty; the path reservation is the durable signal — PutRolePermissionsBoundary still
    rejects every policy found there identically with PolicyNotAttachable."""
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="AWS", PathPrefix="/aws-service-role/", MaxItems=200):
        policies = page.get("Policies", [])
        if policies:
            return policies[0]["Arn"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
