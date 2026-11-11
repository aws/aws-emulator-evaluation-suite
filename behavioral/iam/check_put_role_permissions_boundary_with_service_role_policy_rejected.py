"""put-role-permissions-boundary-with-service-role-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-role-permissions-boundary-with-service-role-policy-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

# A real AWS managed policy that is scoped exclusively to a service-linked role and is not
# eligible to be attached to arbitrary roles or used as a permissions boundary.
_SERVICE_ROLE_POLICY_ARN = "arn:aws:iam::aws:policy/aws-service-role/AmazonEKSServiceRolePolicy"

# An ordinary attachable AWS managed policy, used as the positive control: without it, a target
# that unconditionally rejects every PutRolePermissionsBoundary call would pass this check too.
_ATTACHABLE_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRolePermissionsBoundary with an AWS service-role-only policy fails with
    PolicyNotAttachable and the exact message and leaves the role's attachable boundary, set
    first, in place."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-boundaryreject-")
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
        Tags=[{"Key": "sim2real", "Value": "put-role-permissions-boundary-with-service-role-policy-rejected"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    # Positive control: an ordinary attachable managed policy is accepted as a boundary.
    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=_ATTACHABLE_POLICY_ARN)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_permissions_boundary(RoleName=role_name)))
    before = iam.get_role(RoleName=role_name)["Role"]
    before_arn = before.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
    assert before_arn == _ATTACHABLE_POLICY_ARN, (
        f"expected the attachable positive-control policy {_ATTACHABLE_POLICY_ARN!r} reflected as "
        f"the role's boundary on an independent GetRole, got {before_arn!r}"
    )

    code, message = _error_code(
        lambda: iam.put_role_permissions_boundary(
            RoleName=role_name, PermissionsBoundary=_SERVICE_ROLE_POLICY_ARN
        )
    )
    assert code == "PolicyNotAttachable", f"expected PolicyNotAttachable, got {code!r}"
    assert message == "Cannot attach AWS reserved policy to an IAM role.", message

    after = iam.get_role(RoleName=role_name)["Role"]
    after_arn = after.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
    assert after_arn == _ATTACHABLE_POLICY_ARN, (
        f"rejected PutRolePermissionsBoundary must leave the existing boundary "
        f"{_ATTACHABLE_POLICY_ARN!r} untouched, got {after_arn!r}"
    )


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting what real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected PolicyNotAttachable, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
