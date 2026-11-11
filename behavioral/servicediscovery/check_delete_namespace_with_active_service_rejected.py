"""delete-namespace-with-active-service-rejected."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-namespace-with-active-service-rejected"
GROUP = "server-side"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteNamespace with a service still in the namespace is refused with ResourceInUse and its exact
    message and leaves the namespace intact; after the service is deleted the same call reaches
    SUCCESS, and GetNamespace and a further mutation answer NamespaceNotFound."""
    sd = ctx.client("servicediscovery")
    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_http_namespace(ctx, ns_name)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    service_id = sd.create_service(
        Name=svc_name, NamespaceId=namespace_id, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Service"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_service(sd, service_id))

    code, message = _error(lambda: sd.delete_namespace(Id=namespace_id))
    assert code == "ResourceInUse", f"expected ResourceInUse, got {code}"
    assert message == "Namespace has associated services; delete the services before deleting the namespace", f"unexpected ResourceInUse message: {message!r}"

    # Effect absent: the namespace is untouched.
    ns = sd.get_namespace(Id=namespace_id)["Namespace"]
    assert ns["Id"] == namespace_id and ns["Name"] == ns_name, (
        f"expected intact namespace Id={namespace_id} Name={ns_name}, got Id={ns.get('Id')} Name={ns.get('Name')}"
    )

    # Positive control: remove the blocking service, then delete succeeds.
    sd.delete_service(Id=service_id)
    del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
    del_op = _wait_operation(ctx, del_op_id)
    assert del_op["Status"] == "SUCCESS", f"namespace delete failed after removing service: {del_op}"

    not_found_code, not_found_message = _error(lambda: sd.get_namespace(Id=namespace_id))
    assert not_found_code == "NamespaceNotFound", f"namespace still resolvable after successful delete: {not_found_code}"
    assert not_found_message == "", (
        f"unexpected GetNamespace message: {not_found_message!r}"
    )

    # Unusable: a mutation against the now-dead namespace id must also fail, not resurrect it.
    resurrect_code, resurrect_message = _error(
        lambda: sd.create_service(Name=ctx.unique_name("sim2real-behav-svc-zombie-"), NamespaceId=namespace_id)
    )
    assert resurrect_code == "NamespaceNotFound", (
        f"CreateService against a deleted namespace should fail NamespaceNotFound, got {resurrect_code}"
    )
    assert resurrect_message == namespace_id, (
        f"unexpected CreateService message: {resurrect_message!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_operation(ctx, operation_id: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> dict[str, Any]:
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    op: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} did not reach a terminal state within {timeout_s}s (last={op})")


def _create_http_namespace(ctx, name: str) -> str:
    sd = ctx.client("servicediscovery")
    op_id = sd.create_http_namespace(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["OperationId"]
    op = _wait_operation(ctx, op_id)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op}"
    namespace_id = op["Targets"]["NAMESPACE"]

    def _cleanup():
        try:
            del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
            _wait_operation(ctx, del_op_id)
        except sd.exceptions.NamespaceNotFound:
            pass

    ctx.on_cleanup(_cleanup)
    return namespace_id


def _safe_delete_service(sd, service_id: str) -> None:
    try:
        sd.delete_service(Id=service_id)
    except sd.exceptions.ServiceNotFound:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
