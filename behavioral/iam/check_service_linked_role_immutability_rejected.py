"""service-linked-role-immutability-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-linked-role-immutability-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_SERVICE_NAME = "elasticbeanstalk.amazonaws.com"
_ROLE_NAME = "AWSServiceRoleForElasticBeanstalk"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRole is rejected on a service-linked role, while UpdateRoleDescription (its documented exception) succeeds."""

    iam = ctx.client("iam")

    role_name, created, original_description = _ensure_service_linked_role(
        iam, _SERVICE_NAME, _ROLE_NAME
    )

    def cleanup():
        try:
            if created:
                task_id = iam.delete_service_linked_role(RoleName=role_name)["DeletionTaskId"]
                deadline = time.monotonic() + 60.0
                while time.monotonic() < deadline:
                    status = iam.get_service_linked_role_deletion_status(
                        DeletionTaskId=task_id
                    )["Status"]
                    if status in ("SUCCEEDED", "FAILED"):
                        break
                    time.sleep(2.0)
            else:
                # We adopted a role this check did not create; restore the description we
                # are about to overwrite rather than leaving our mutation behind.
                iam.update_role_description(
                    RoleName=role_name, Description=original_description or ""
                )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(cleanup)

    # DeleteRole must reject a service-linked role; DeleteServiceLinkedRole is required instead.
    code_delete, msg_delete = _error(lambda: iam.delete_role(RoleName=role_name))
    assert code_delete == "UnmodifiableEntity", (
        f"expected UnmodifiableEntity from DeleteRole on a service-linked role, got {code_delete}"
    )
    want = (f"Cannot perform the operation on the protected role '{role_name}' - "
            "this role is only modifiable by AWS")
    assert msg_delete == want, f"DeleteRole message: wanted {want!r}, got {msg_delete!r}"

    # UpdateRoleDescription is IAM's documented, narrow exception for service-linked roles: it
    # is the one field the console/API let you edit without going through the owning service,
    # while permissions/trust/path stay immutable. So it succeeds here rather than being rejected.
    new_description = "sim2real-updated-description"
    iam.update_role_description(RoleName=role_name, Description=new_description)
    updated = iam.get_role(RoleName=role_name)["Role"]
    assert updated["Description"] == new_description, (
        "UpdateRoleDescription did not update the service-linked role's description"
    )

    # the role's identity remains unaffected by the rejected DeleteRole call and the allowed
    # description update
    still_there = iam.get_role(RoleName=role_name)["Role"]
    assert still_there["RoleName"] == role_name, (
        f"expected role {role_name!r} to remain after the rejected DeleteRole, "
        f"got {still_there.get('RoleName')!r}"
    )


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _ensure_service_linked_role(iam, aws_service_name: str, role_name: str):
    """Create-or-adopt: use the role if it already exists (a shared, fixed-name singleton
    also touched by other service-linked-role checks) rather than failing the check just
    because it is present."""
    from botocore.exceptions import ClientError

    try:
        existing = iam.get_role(RoleName=role_name)["Role"]
        return role_name, False, existing.get("Description")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise

    iam.create_service_linked_role(AWSServiceName=aws_service_name)
    return role_name, True, None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
