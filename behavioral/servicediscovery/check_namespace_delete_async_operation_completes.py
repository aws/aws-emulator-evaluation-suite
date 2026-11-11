"""namespace-delete-async-operation-completes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-delete-async-operation-completes"
GROUP = "state-machine"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNamespace's operation is seen SUBMITTED or PENDING while the namespace still resolves,
    then reaches SUCCESS, and only afterward does GetNamespace answer NamespaceNotFound with an empty
    message."""
    sd = ctx.client("servicediscovery")
    name = f"{ctx.unique_name('sim2real-del-ns')}.com"

    create_resp = sd.create_public_dns_namespace(
        Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    create_op = _wait_operation(ctx, create_resp["OperationId"])
    assert create_op["Status"] == "SUCCESS", f"namespace create failed: {create_op}"
    ns_id = create_op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(ctx, ns_id))

    delete_resp = sd.delete_namespace(Id=ns_id)
    delete_op_id = delete_resp["OperationId"]

    saw_pending_with_namespace_present = False
    status = None
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline:
        op_state = sd.get_operation(OperationId=delete_op_id)["Operation"]
        status = op_state["Status"]
        if status in ("SUBMITTED", "PENDING"):
            # While the delete Operation has not reached a terminal state, the namespace must
            # still be visible -- deletion is not applied synchronously with the API call.
            still_there = sd.get_namespace(Id=ns_id)["Namespace"]
            assert still_there["Id"] == ns_id, (
                f"namespace {ns_id} unreadable while delete Operation is {status}: {still_there}"
            )
            saw_pending_with_namespace_present = True
        if status in ("SUCCESS", "FAIL"):
            break
        time.sleep(2)
    assert status == "SUCCESS", f"delete operation ended in {status}"
    assert saw_pending_with_namespace_present, (
        "never observed the delete Operation in SUBMITTED/PENDING with the namespace still "
        "present -- cannot confirm the pre-SUCCESS invariant"
    )

    # Only now, after the Operation reports SUCCESS, should GetNamespace eventually 404.
    deadline = _deadline(ctx, 120.0)
    while time.monotonic() < deadline:
        try:
            sd.get_namespace(Id=ns_id)
        except ClientError as e:
            code, message = e.response["Error"]["Code"], e.response["Error"].get("Message")
            assert code == "NamespaceNotFound", f"expected NamespaceNotFound after delete, got {code}"
            assert message == "", f"unexpected GetNamespace message: {message!r}"
            return
        time.sleep(2)
    raise AssertionError("GetNamespace never reported NamespaceNotFound after delete Operation SUCCESS")


# ===== helpers =====
def _deadline(ctx, cap_s: float) -> float:
    """A monotonic deadline `cap_s` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (cap_s if left is None else min(cap_s, max(left - 5.0, 1.0)))


def _wait_operation(ctx, operation_id, timeout_s: float = 240.0, interval_s: float = 3.0):
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        if time.monotonic() > deadline:
            raise AssertionError(
                f"operation {operation_id} did not reach a terminal state within {timeout_s}s "
                f"(last status={op['Status']})"
            )
        time.sleep(interval_s)


def _safe_delete_namespace(ctx, namespace_id: str) -> None:
    sd = ctx.client("servicediscovery")
    try:
        resp = sd.delete_namespace(Id=namespace_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NamespaceNotFound":
            raise
        return
    op_id = resp.get("OperationId")
    if not op_id:
        return
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            op = sd.get_operation(OperationId=op_id)["Operation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "OperationNotFound":
                raise
            return
        if op["Status"] in ("SUCCESS", "FAIL"):
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
