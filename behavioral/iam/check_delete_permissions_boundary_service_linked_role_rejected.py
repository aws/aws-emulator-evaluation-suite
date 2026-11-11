"""delete-permissions-boundary-service-linked-role-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-permissions-boundary-service-linked-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]

SLR_SERVICE_NAME = "lightsail.amazonaws.com"
SLR_ROLE_NAME = "AWSServiceRoleForLightsail"

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRolePermissionsBoundary on a service-linked role fails UnmodifiableEntity, while an
    ordinary role with no boundary gets NoSuchEntity and, once it has one, has it removed."""
    iam = ctx.client("iam")
    _ensure_service_linked_role(ctx, SLR_SERVICE_NAME, SLR_ROLE_NAME)

    role_name = ctx.unique_name("sim2real-behav-role-")
    role_id = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))[
        "Role"
    ]["RoleId"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # Matched control: an ordinary role with no boundary set (same "no boundary" state as the
    # SLR below) is rejected NoSuchEntity, not UnmodifiableEntity.
    control_code, control_message = _error(
        lambda: iam.delete_role_permissions_boundary(RoleName=role_name)
    )
    assert control_code == "NoSuchEntity", (
        f"an ordinary role with no boundary set should get NoSuchEntity, got {control_code!r}"
    )
    expected_control = f"Principal {role_id} does not have scope"
    assert control_message == expected_control, (
        f"expected message {expected_control!r}, got {control_message!r}"
    )

    # The SLR, also with no boundary ever set, is rejected UnmodifiableEntity instead -- the
    # immutable-entity check fires before AWS ever asks "is there a boundary to delete".
    code, message = _error(lambda: iam.delete_role_permissions_boundary(RoleName=SLR_ROLE_NAME))
    assert code == "UnmodifiableEntity", f"expected UnmodifiableEntity, got {code!r}"
    expected = (
        f"Cannot perform the operation on the protected role '{SLR_ROLE_NAME}' - "
        "this role is only modifiable by AWS"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same ordinary role, once it actually has a boundary, has it removed.
    iam.put_role_permissions_boundary(RoleName=role_name, PermissionsBoundary=READONLY_ARN)
    role_with_boundary = iam.get_role(RoleName=role_name)["Role"]
    assert role_with_boundary["PermissionsBoundary"]["PermissionsBoundaryArn"] == READONLY_ARN, (
        f"put_role_permissions_boundary did not stick: "
        f"{role_with_boundary.get('PermissionsBoundary')!r}"
    )

    iam.delete_role_permissions_boundary(RoleName=role_name)
    role_without_boundary = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in role_without_boundary, (
        f"boundary still present after delete: "
        f"{role_without_boundary.get('PermissionsBoundary')!r}"
    )


def _error(fn: Callable[[], Any]):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _ensure_service_linked_role(ctx, aws_service_name: str, role_name: str) -> None:
    """Create the service-linked role if it doesn't already exist. Only registers a
    cleanup deletion if this call actually created it."""
    iam = ctx.client("iam")
    from botocore.exceptions import ClientError

    try:
        iam.get_role(RoleName=role_name)
        return  # already existed before this check; leave it alone
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

    iam.create_service_linked_role(AWSServiceName=aws_service_name)

    def _cleanup():
        try:
            iam.delete_service_linked_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
