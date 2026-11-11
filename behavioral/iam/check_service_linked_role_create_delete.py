"""service-linked-role-create-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-linked-role-create-delete"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A service-linked role creation followed by a deletion request reaches a terminal SUCCEEDED status."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-behav-")[-20:]  # CustomSuffix pattern: [\w+=,.@-]+; keep role name <64 chars

    created = iam.create_service_linked_role(
        AWSServiceName="autoscaling.amazonaws.com", CustomSuffix=suffix
    )["Role"]
    role_name = created["RoleName"]
    assert role_name.startswith("AWSServiceRoleForAutoScaling"), (
        f"expected AWSServiceRoleForAutoScaling* role name, got {role_name!r}"
    )
    assert role_name.endswith(suffix), f"expected role name to end with {suffix!r}, got {role_name!r}"

    deleted_ok = {"value": False}

    def _cleanup():
        if deleted_ok["value"]:
            return
        try:
            task_id = iam.delete_service_linked_role(RoleName=role_name)["DeletionTaskId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return
            raise
        status = _poll_deletion_status(iam, task_id, timeout_s=60, role_name=role_name)
        if status != "SUCCEEDED":
            raise RuntimeError(f"service-linked role {role_name!r} deletion ended {status}")

    ctx.on_cleanup(_cleanup)

    got = iam.get_role(RoleName=role_name)["Role"]
    assert got["Path"] == "/aws-service-role/autoscaling.amazonaws.com/", (
        f"expected the service-linked-role path, got {got['Path']!r}"
    )

    deletion_task_id = iam.delete_service_linked_role(RoleName=role_name)["DeletionTaskId"]
    status = _poll_deletion_status(iam, deletion_task_id, timeout_s=60, role_name=role_name)
    assert status == "SUCCEEDED", f"expected SUCCEEDED, got {status}"
    deleted_ok["value"] = True

    # Independent read at the destination: GetRole (not the delete's own response) must now
    # refuse with the specific not-found code; an unexpected success raises immediately, so an
    # accepted read fails loudly rather than on an unrelated code mismatch.
    try:
        still_there = iam.get_role(RoleName=role_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchEntity", f"expected NoSuchEntity reading the deleted role, got {code!r}"
        message = exc.response["Error"].get("Message")
        expected = f"The role with name {role_name} cannot be found."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"expected GetRole to fail with NoSuchEntity after deletion, but it returned {still_there!r}"
        )

    # A mutation on the dead id must also fail: re-deleting an already-deleted service-linked
    # role is not a silent no-op.
    try:
        redelete = iam.delete_service_linked_role(RoleName=role_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchEntity", (
            f"expected NoSuchEntity re-deleting an already-deleted role, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        expected = "Cannot find the service role to delete."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"expected a second DeleteServiceLinkedRole on the same role to fail, but it returned {redelete!r}"
        )


# ===== helpers =====


def _role_exists(iam, role_name) -> bool:
    """True while GetRole still returns the role, False once it refuses with NoSuchEntity;
    any other error propagates."""
    from botocore.exceptions import ClientError

    try:
        iam.get_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise
    return True


def _poll_deletion_status(iam, deletion_task_id, timeout_s=60.0, interval_s=2.0, role_name=None):
    """Poll GetServiceLinkedRoleDeletionStatus until it reaches a terminal state.

    On real AWS the deletion can complete so quickly that the DeletionTaskId is no
    longer tracked by the time we poll it, and GetServiceLinkedRoleDeletionStatus
    raises NoSuchEntity ("Cannot find deletion status for given id") instead of ever
    returning a SUCCEEDED status payload. That NoSuchEntity is only treated as an
    implicit SUCCEEDED when we can independently confirm the role itself is gone;
    otherwise it is a genuine failure and is re-raised.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            resp = iam.get_service_linked_role_deletion_status(DeletionTaskId=deletion_task_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity" and role_name is not None:
                # The deletion task can complete and be pruned/forgotten before we
                # poll it, so the deletion-status lookup itself starts raising
                # NoSuchEntity. That's only an implicit SUCCEEDED once the role is
                # actually gone -- and the role's own disappearance can lag slightly
                # behind the task being forgotten, so poll for that confirmation too
                # instead of checking it exactly once.
                role_gone_deadline = time.monotonic() + timeout_s
                while time.monotonic() < role_gone_deadline:
                    if not _role_exists(iam, role_name):
                        return "SUCCEEDED"
                    time.sleep(interval_s)
            raise
        status = resp["Status"]
        if status in ("SUCCEEDED", "FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"service-linked role deletion never reached a terminal state (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
