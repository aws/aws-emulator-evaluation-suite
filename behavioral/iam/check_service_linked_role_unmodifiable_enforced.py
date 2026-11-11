"""service-linked-role-unmodifiable-enforced."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-linked-role-unmodifiable-enforced"
GROUP = 'errors'
SERVICES = ['iam']


def _err(fn):
    """The (error code, message) fn() raises; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=3.0, description="condition"):
    import time as _t
    deadline = _t.monotonic() + timeout_s
    last = None
    while _t.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        _t.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A service-linked role rejects DeleteRolePermissionsBoundary and DeleteRole as
    UnmodifiableEntity, accepts description updates, and is removed by DeleteServiceLinkedRole."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-behav-slr-")
    created = iam.create_service_linked_role(
        AWSServiceName="autoscaling.amazonaws.com",
        CustomSuffix=suffix,
        Description="sim2real-behav SLR unmodifiable-enforcement check",
    )
    role_name = created["Role"]["RoleName"]
    role_arn = created["Role"]["Arn"]
    iam.tag_role(RoleName=role_name, Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _cleanup_slr():
        try:
            resp = iam.delete_service_linked_role(RoleName=role_name)
            task_id = resp["DeletionTaskId"]

            def _poll():
                try:
                    return iam.get_service_linked_role_deletion_status(DeletionTaskId=task_id)
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                        return {"Status": "PENDING_LOOKUP"}
                    raise

            _poll_until(
                _poll,
                lambda r: r["Status"] in ("SUCCEEDED", "FAILED"),
                timeout_s=60,
                interval_s=3,
                description="SLR deletion (cleanup fallback)",
            )
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_slr)

    # Description IS a documented, mutable exception on a service-linked role.
    iam.update_role(RoleName=role_name, Description="sim2real-behav-updated-via-updaterole")
    after_update_role = iam.get_role(RoleName=role_name)["Role"]
    assert after_update_role["Description"] == "sim2real-behav-updated-via-updaterole", (
        f"UpdateRole should be allowed to change an SLR's description, got "
        f"{after_update_role.get('Description')!r}"
    )

    iam.update_role_description(
        RoleName=role_name, Description="sim2real-behav-updated-via-updateroledescription"
    )
    after_update_desc = iam.get_role(RoleName=role_name)["Role"]
    assert after_update_desc["Description"] == "sim2real-behav-updated-via-updateroledescription", (
        f"UpdateRoleDescription should be allowed to change an SLR's description, got "
        f"{after_update_desc.get('Description')!r}"
    )

    # A permissions boundary can never be set/removed on a service-linked role.
    code_delete_boundary, msg_delete_boundary = _err(
        lambda: iam.delete_role_permissions_boundary(RoleName=role_name)
    )
    assert code_delete_boundary == "UnmodifiableEntity", (
        f"DeleteRolePermissionsBoundary on a service-linked role: expected UnmodifiableEntity, "
        f"got {code_delete_boundary}"
    )
    protected = (f"Cannot perform the operation on the protected role '{role_name}' - "
                 "this role is only modifiable by AWS")
    assert msg_delete_boundary == protected, (
        f"DeleteRolePermissionsBoundary message: wanted {protected!r}, got {msg_delete_boundary!r}"
    )

    # Deleting it OUTSIDE the managed workflow (plain DeleteRole) is rejected.
    code_delete_role, msg_delete_role = _err(lambda: iam.delete_role(RoleName=role_name))
    assert code_delete_role == "UnmodifiableEntity", (
        f"DeleteRole (outside the managed workflow) on a service-linked role: "
        f"expected UnmodifiableEntity, got {code_delete_role}"
    )
    assert msg_delete_role == protected, (
        f"DeleteRole message: wanted {protected!r}, got {msg_delete_role!r}"
    )

    # The rejected DeleteRole must not have disturbed the role.
    still_there = iam.get_role(RoleName=role_name)
    assert still_there["Role"]["Arn"] == role_arn, (
        f"expected {role_arn!r} unchanged after the rejected DeleteRole, "
        f"got {still_there['Role'].get('Arn')!r}"
    )

    delete_resp = iam.delete_service_linked_role(RoleName=role_name)
    task_id = delete_resp["DeletionTaskId"]

    def _poll_deletion_status():
        try:
            return iam.get_service_linked_role_deletion_status(DeletionTaskId=task_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return {"Status": "PENDING_LOOKUP"}
            raise

    status = _poll_until(
        _poll_deletion_status,
        lambda r: r["Status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=60,
        interval_s=3,
        description="service-linked role deletion task reaches a terminal state",
    )
    assert status["Status"] == "SUCCEEDED", f"expected SUCCEEDED, got {status}"
    code_final, msg_final = _err(lambda: iam.get_role(RoleName=role_name))
    assert code_final == "NoSuchEntity", f"expected role gone after managed deletion, got {code_final}"
    want = f"The role with name {role_name} cannot be found."
    assert msg_final == want, f"GetRole message: wanted {want!r}, got {msg_final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
