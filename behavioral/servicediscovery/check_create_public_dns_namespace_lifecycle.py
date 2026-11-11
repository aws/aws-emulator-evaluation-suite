"""create-public-dns-namespace-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-public-dns-namespace-lifecycle"
GROUP = "state-machine"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePublicDnsNamespace follows the same create->ACTIVE->delete->404 async-Operation
    transition as private namespaces: SUCCESS makes the namespace visible via GetNamespace,
    and DeleteNamespace reaching SUCCESS removes it."""
    sd = ctx.client("servicediscovery")
    name = f"{ctx.unique_name('sim2real-pub-ns')}.com"

    create_resp = sd.create_public_dns_namespace(Name=name, CreatorRequestId=ctx.unique_name("sim2real-cr-"))
    op = _wait_operation(ctx, create_resp["OperationId"])
    assert op["Status"] == "SUCCESS", f"create ended in {op['Status']}: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(ctx, ns_id))

    got = sd.get_namespace(Id=ns_id)["Namespace"]
    assert got["Id"] == ns_id, f"expected Id {ns_id!r}, got {got['Id']!r}"
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["Type"] == "DNS_PUBLIC", f"expected Type DNS_PUBLIC, got {got['Type']!r}"

    delete_resp = sd.delete_namespace(Id=ns_id)
    del_op = _wait_operation(ctx, delete_resp["OperationId"])
    assert del_op["Status"] == "SUCCESS", f"delete ended in {del_op['Status']}: {del_op.get('ErrorMessage')}"

    code, message = _error(lambda: sd.get_namespace(Id=ns_id))
    assert code == "NamespaceNotFound", f"expected NamespaceNotFound after delete, got {code!r}"
    assert message == "", f"unexpected GetNamespace message: {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
