"""update-namespace-not-found-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-namespace-not-found-error"
GROUP = "error-semantics"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePrivateDnsNamespace against a namespace ID that was deleted returns
    NamespaceNotFound, and does not resurrect the namespace."""
    sd = ctx.client("servicediscovery")
    name = f"{ctx.unique_name('sim2real-pubns-')}.com"

    create_op_id = sd.create_public_dns_namespace(Name=name)["OperationId"]
    op = _poll_operation(ctx, sd, create_op_id, timeout_s=180.0)
    assert op["Status"] == "SUCCESS", f"create failed: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]

    delete_op_id = sd.delete_namespace(Id=ns_id)["OperationId"]
    del_op = _poll_operation(ctx, sd, delete_op_id, timeout_s=180.0)
    assert del_op["Status"] == "SUCCESS", f"delete failed: {del_op.get('ErrorMessage')}"

    # Confirm it is really gone before probing update semantics on the dead ID.
    gone = _client_error(lambda: sd.get_namespace(Id=ns_id))
    assert gone.get("Code") == "NamespaceNotFound", f"expected NamespaceNotFound, got {gone!r}"
    assert gone.get("Message") == "", f"expected an empty NamespaceNotFound message, got {gone.get('Message')!r}"

    error = _client_error(
        lambda: sd.update_private_dns_namespace(Id=ns_id, Namespace={"Description": "resurrect me"})
    )
    assert error.get("Code") == "NamespaceNotFound", f"expected NamespaceNotFound, got {error!r}"
    assert error.get("Message") == ns_id, f"expected NamespaceNotFound message {ns_id!r}, got {error.get('Message')!r}"

    # Effect absent: still gone, not partially recreated by the failed update.
    still_gone = _client_error(lambda: sd.get_namespace(Id=ns_id))
    assert still_gone.get("Code") == "NamespaceNotFound", f"expected NamespaceNotFound, got {still_gone!r}"
    assert still_gone.get("Message") == "", (
        f"expected an empty NamespaceNotFound message, got {still_gone.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises, because a target accepting a call real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_operation(ctx, sd, operation_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(
        f"operation {operation_id} did not reach a terminal state within {timeout_s}s "
        f"(last status={op['Status'] if op else None})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
