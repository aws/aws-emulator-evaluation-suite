"""service-linked-role-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-linked-role-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]

_SERVICE_NAME = "autoscaling.amazonaws.com"
_ROLE_PREFIX = "AWSServiceRoleForAutoScaling"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateServiceLinkedRole creates the role, DeleteServiceLinkedRole starts async
    deletion tracked to completion via GetServiceLinkedRoleDeletionStatus, and the role
    disappears from IAM once the deletion task SUCCEEDED."""
    iam = ctx.client("iam")

    raw_name = ctx.unique_name("sim2realslr")
    suffix = "".join(ch for ch in raw_name if ch.isalnum())[-32:] or "sim2realslr"
    role = iam.create_service_linked_role(
        AWSServiceName=_SERVICE_NAME,
        CustomSuffix=suffix,
        Description="sim2real behavioral test service-linked role",
    )["Role"]
    role_name = role["RoleName"]
    ctx.on_cleanup(lambda: _best_effort_delete_slr(iam, role_name))

    assert role_name.startswith(_ROLE_PREFIX), f"unexpected service-linked role name {role_name}"
    assert role_name.endswith(suffix), f"custom suffix not applied to role name {role_name}"
    assert role["Path"] == f"/aws-service-role/{_SERVICE_NAME}/", f"unexpected path {role['Path']}"

    fetched = iam.get_role(RoleName=role_name)["Role"]
    assert fetched["RoleName"] == role_name, f"expected independent read to see {role_name}, got {fetched['RoleName']}"

    deletion_task_id = iam.delete_service_linked_role(RoleName=role_name)["DeletionTaskId"]

    status = _poll_until_terminal(iam, deletion_task_id, role_name, timeout_s=120.0)
    assert status == "SUCCEEDED", f"expected deletion task to SUCCEED, got {status}"

    code, msg = _error(lambda: iam.get_role(RoleName=role_name))
    assert code == "NoSuchEntity", f"expected role gone after successful deletion, got {code}"
    want = f"The role with name {role_name} cannot be found."
    assert msg == want, f"GetRole message: wanted {want!r}, got {msg!r}"

    redelete_code, redelete_msg = _error(lambda: iam.delete_service_linked_role(RoleName=role_name))
    assert redelete_code == "NoSuchEntity", (
        f"expected a second delete on the already-deleted role to fail NoSuchEntity, got {redelete_code}"
    )
    want_redelete = "Cannot find the service role to delete."
    assert redelete_msg == want_redelete, (
        f"DeleteServiceLinkedRole message: wanted {want_redelete!r}, got {redelete_msg!r}"
    )


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _role_gone(iam, role_name) -> bool:
    from botocore.exceptions import ClientError

    try:
        iam.get_role(RoleName=role_name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return True
        raise
    return False


def _poll_until_terminal(
    iam, deletion_task_id: str, role_name: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    status = "NOT_STARTED"
    while time.monotonic() < deadline:
        try:
            resp = iam.get_service_linked_role_deletion_status(DeletionTaskId=deletion_task_id)
            status = resp["Status"]
            if status in ("SUCCEEDED", "FAILED"):
                return status
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
            # The deletion-status record can be momentarily unresolvable right after
            # DeleteServiceLinkedRole is issued (IAM eventual consistency), or the task
            # completed and its status record already expired. Either way, if the role
            # itself is already gone, the deletion has (successfully) completed.
            if _role_gone(iam, role_name):
                return "SUCCEEDED"
        time.sleep(interval_s)
    raise AssertionError(f"deletion task did not reach a terminal state within {timeout_s}s (last={status})")


def _best_effort_delete_slr(iam, role_name) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_service_linked_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
