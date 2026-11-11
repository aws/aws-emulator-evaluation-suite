"""create-service-linked-role-unsupported-service-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-service-linked-role-unsupported-service-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]

_BOGUS_SERVICE_NAME = "sim2real-not-a-real-service.amazonaws.com"
_REAL_SERVICE_NAME = "autoscaling.amazonaws.com"
_REAL_ROLE_PREFIX = "AWSServiceRoleForAutoScaling"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateServiceLinkedRole for an unknown service principal is refused with AccessDenied.

    A real service-linked role is created first, so the refusal is not a missing permission.
    """
    iam = ctx.client("iam")

    suffix = "".join(ch for ch in ctx.unique_name("sim2realslrneg") if ch.isalnum())[-32:] or "sim2realslrneg"
    control = iam.create_service_linked_role(
        AWSServiceName=_REAL_SERVICE_NAME, CustomSuffix=suffix
    )["Role"]
    control_role_name = control["RoleName"]
    assert control_role_name.startswith(_REAL_ROLE_PREFIX), (
        f"positive control: expected role name starting with {_REAL_ROLE_PREFIX!r}, "
        f"got {control_role_name!r}"
    )
    ctx.on_cleanup(lambda: _delete_slr(iam, control_role_name))

    code, message = _error(
        lambda: iam.create_service_linked_role(AWSServiceName=_BOGUS_SERVICE_NAME)
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    assert message == (
        f"{_BOGUS_SERVICE_NAME} is not a valid AWS service name (Service Principal)"
    ), f"unsupported-service CreateServiceLinkedRole message: {message!r}"

    roles = iam.list_roles(PathPrefix="/aws-service-role/")["Roles"]
    assert not any(_BOGUS_SERVICE_NAME in r["Path"] for r in roles)
    assert any(r["RoleName"] == control_role_name for r in roles), (
        "positive-control role missing from the same listing the rejection is verified against"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _delete_slr(iam, role_name: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    from botocore.exceptions import ClientError

    try:
        task_id = iam.delete_service_linked_role(RoleName=role_name)["DeletionTaskId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = iam.get_service_linked_role_deletion_status(DeletionTaskId=task_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            return
        if resp["Status"] in ("SUCCEEDED", "FAILED"):
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
