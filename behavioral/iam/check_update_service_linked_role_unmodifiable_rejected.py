"""update-service-linked-role-unmodifiable-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-service-linked-role-unmodifiable-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]

SLR_SERVICE_NAME = "elasticbeanstalk.amazonaws.com"
SLR_ROLE_NAME = "AWSServiceRoleForElasticBeanstalk"

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAssumeRolePolicy on a service-linked role fails with UnmodifiableEntity and
    its exact message and leaves the trust policy unchanged, while UpdateRoleDescription on
    it succeeds and the same trust-policy update succeeds on an ordinary role."""
    iam = ctx.client("iam")
    _ensure_service_linked_role(ctx, SLR_SERVICE_NAME, SLR_ROLE_NAME)

    slr_before = iam.get_role(RoleName=SLR_ROLE_NAME)["Role"]
    trust_before = slr_before["AssumeRolePolicyDocument"]
    original_description = slr_before.get("Description")

    code1, message1 = _error(
        lambda: iam.update_assume_role_policy(
            RoleName=SLR_ROLE_NAME, PolicyDocument=json.dumps(TRUST_POLICY)
        )
    )
    assert code1 == "UnmodifiableEntity", (
        f"expected UnmodifiableEntity from UpdateAssumeRolePolicy, got {code1!r}"
    )
    expected1 = (
        f"Cannot perform the operation on the protected role '{SLR_ROLE_NAME}' - "
        "this role is only modifiable by AWS"
    )
    assert message1 == expected1, f"expected message {expected1!r}, got {message1!r}"

    slr_after = iam.get_role(RoleName=SLR_ROLE_NAME)["Role"]
    assert slr_after["AssumeRolePolicyDocument"] == trust_before, (
        f"trust policy must be unchanged after the rejected UpdateAssumeRolePolicy call, "
        f"expected {trust_before!r}, got {slr_after['AssumeRolePolicyDocument']!r}"
    )

    # Description edits are explicitly permitted for service-linked roles (unlike trust
    # policy or permissions changes), so UpdateRoleDescription must succeed here.
    ctx.on_cleanup(
        lambda: iam.update_role_description(
            RoleName=SLR_ROLE_NAME, Description=original_description or ""
        )
    )
    iam.update_role_description(RoleName=SLR_ROLE_NAME, Description="sim2real-behav-updated")
    slr_after_desc = iam.get_role(RoleName=SLR_ROLE_NAME)["Role"]
    assert slr_after_desc.get("Description") == "sim2real-behav-updated", (
        f"UpdateRoleDescription is the documented mutable exception for a service-linked role, "
        f"expected Description='sim2real-behav-updated', got {slr_after_desc.get('Description')!r}"
    )

    # Positive control: the exact same trust-policy update the SLR rejected succeeds
    # against an ordinary role.
    role_name = ctx.unique_name("sim2real-behav-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="original",
        Tags=[{"Key": "sim2real", "Value": "update-service-linked-role-unmodifiable-rejected"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(TRUST_POLICY))
    iam.update_role_description(RoleName=role_name, Description="updated-description")
    updated = iam.get_role(RoleName=role_name)["Role"]
    assert updated["Description"] == "updated-description", (
        f"positive control: the identical trust-policy update the SLR rejected must succeed "
        f"against an ordinary role, and its description update must stick, got "
        f"{updated.get('Description')!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ensure_service_linked_role(ctx, aws_service_name: str, role_name: str) -> None:
    """Create the service-linked role if it doesn't already exist. Only registers a
    cleanup deletion if this call actually created it (so we don't tear down a role that
    was already in use before this check ran)."""
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
