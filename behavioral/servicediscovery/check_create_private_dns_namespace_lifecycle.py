"""create-private-dns-namespace-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-private-dns-namespace-lifecycle"
GROUP = "state-machine"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePrivateDnsNamespace's Operation reaches SUCCESS, the namespace is then visible
    via GetNamespace, and DeleteNamespace's own Operation reaching SUCCESS removes it so a
    subsequent GetNamespace 404s and a repeat DeleteNamespace on the dead id also 404s."""
    sd = ctx.client("servicediscovery")
    vpc_id = _get_vpc_id(ctx)
    name = f"{ctx.unique_name('sim2real-priv-ns')}.example.com"

    create_resp = sd.create_private_dns_namespace(
        Name=name, Vpc=vpc_id, CreatorRequestId=ctx.unique_name("sim2real-cr-")
    )
    op = _wait_operation(ctx, create_resp["OperationId"])
    assert op["Status"] == "SUCCESS", f"create ended in {op['Status']}: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(ctx, ns_id))

    got = sd.get_namespace(Id=ns_id)["Namespace"]
    assert got["Id"] == ns_id, f"expected GetNamespace to return {ns_id}, got {got.get('Id')}"
    assert got["Name"] == name, f"expected namespace name {name!r}, got {got.get('Name')!r}"
    assert got["Type"] == "DNS_PRIVATE", f"expected type DNS_PRIVATE, got {got.get('Type')}"

    delete_resp = sd.delete_namespace(Id=ns_id)
    del_op = _wait_operation(ctx, delete_resp["OperationId"])
    assert del_op["Status"] == "SUCCESS", f"delete ended in {del_op['Status']}: {del_op.get('ErrorMessage')}"

    code, message = _error(lambda: sd.get_namespace(Id=ns_id))
    assert code == "NamespaceNotFound", f"expected NamespaceNotFound after delete, got {code}"
    assert message == "", f"unexpected GetNamespace message: {message!r}"

    # A mutation on the now-dead id must also fail, not just a read.
    redelete_code, redelete_message = _error(lambda: sd.delete_namespace(Id=ns_id))
    assert redelete_code == "NamespaceNotFound", (
        f"expected DeleteNamespace on an already-deleted id to fail NamespaceNotFound, got {redelete_code}"
    )
    assert redelete_message == ns_id, (
        f"unexpected DeleteNamespace message: {redelete_message!r}"
    )


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


def _get_vpc_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    return vpcs[0]["VpcId"]


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
