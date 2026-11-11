"""create-namespace-idempotent-retry-same-id."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-namespace-idempotent-retry-same-id"
GROUP = "error-semantics"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying CreatePrivateDnsNamespace with the same CreatorRequestId and
    identical parameters returns the original operation rather than creating a
    duplicate namespace."""
    sd = ctx.client("servicediscovery")
    vpc_id = _get_or_create_vpc(ctx)
    name = f"{ctx.unique_name('sim2real-privns-')}.com"
    creator_request_id = ctx.unique_name("sim2real-crid-")

    first = sd.create_private_dns_namespace(
        Name=name, Vpc=vpc_id, CreatorRequestId=creator_request_id
    )
    second = sd.create_private_dns_namespace(
        Name=name, Vpc=vpc_id, CreatorRequestId=creator_request_id
    )
    assert first["OperationId"] == second["OperationId"], (
        "identical retry with the same CreatorRequestId must return the same OperationId"
    )

    op = _poll_operation(ctx, sd, first["OperationId"], timeout_s=240.0)
    assert op["Status"] == "SUCCESS", f"create failed: {op.get('ErrorMessage')}"
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(sd, ns_id))

    matches = sd.list_namespaces(Filters=[{"Name": "NAME", "Values": [name], "Condition": "EQ"}])[
        "Namespaces"
    ]
    assert len(matches) == 1, f"expected exactly one namespace named {name!r}, got {len(matches)}"
    assert matches[0]["Id"] == ns_id, f"listed namespace id {matches[0]['Id']!r} != created id {ns_id!r}"

    # The cleanup delete is a free negative: prove it actually removed the namespace
    # rather than merely being called.
    delete_op_id = sd.delete_namespace(Id=ns_id)["OperationId"]
    delete_op = _poll_operation(ctx, sd, delete_op_id, timeout_s=180.0)
    assert delete_op["Status"] == "SUCCESS", f"delete failed: {delete_op.get('ErrorMessage')}"

    get_code, get_message = _error(lambda: sd.get_namespace(Id=ns_id))
    assert get_code == "NamespaceNotFound", (
        f"expected NamespaceNotFound reading deleted namespace {ns_id!r}, got {get_code}"
    )
    assert get_message == "", f"unexpected GetNamespace message: {get_message!r}"

    redelete_code, redelete_message = _error(lambda: sd.delete_namespace(Id=ns_id))
    assert redelete_code == "NamespaceNotFound", (
        f"expected NamespaceNotFound re-deleting already-deleted namespace {ns_id!r}, got {redelete_code}"
    )
    assert redelete_message == ns_id, (
        f"unexpected DeleteNamespace message: {redelete_message!r}"
    )


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


def _get_or_create_vpc(ctx):
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    return vpcs[0]["VpcId"]


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _safe_delete_namespace(sd, ns_id):
    if not ns_id:
        return
    try:
        sd.delete_namespace(Id=ns_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NamespaceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
