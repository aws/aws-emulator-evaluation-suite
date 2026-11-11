"""duplicate-request-idempotent-create-private-dns."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-request-idempotent-create-private-dns"
GROUP = "error-semantics"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreatePrivateDnsNamespace calls with one CreatorRequestId and identical parameters
    resolve to one operation (or the second is refused with DuplicateRequest naming it), that
    operation reaches SUCCESS, and exactly one namespace exists under the name."""
    sd = ctx.client("servicediscovery")
    vpc_id = _create_vpc(ctx)
    name = f"{ctx.unique_name('sim2real-dup')}.example.com"
    creator_request_id = ctx.unique_name("sim2real-crid-")

    def _do_create():
        try:
            return ("ok", sd.create_private_dns_namespace(Name=name, Vpc=vpc_id, CreatorRequestId=creator_request_id))
        except ClientError as e:
            return ("err", e)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut1 = pool.submit(_do_create)
        fut2 = pool.submit(_do_create)
        kind1, res1 = fut1.result()
        kind2, res2 = fut2.result()

    results = [(kind1, res1), (kind2, res2)]
    oks = [r for k, r in results if k == "ok"]
    errs = [r for k, r in results if k == "err"]

    assert len(oks) >= 1, f"expected at least one of the two concurrent creates to succeed: {results}"
    op_id_winner = oks[0]["OperationId"]
    # Registered as soon as the operation id exists, so a failure below still removes the namespace.
    ctx.on_cleanup(lambda: _delete_namespace_of_operation(ctx, op_id_winner))

    if errs:
        # The loser was rejected as an in-progress duplicate of the winner's operation.
        err = errs[0]
        code = err.response["Error"]["Code"]
        assert code == "DuplicateRequest", f"expected DuplicateRequest, got {code}"
        dup_op_id = err.response.get("DuplicateOperationId") or err.response["Error"].get("DuplicateOperationId")
        assert dup_op_id == op_id_winner, (
            f"expected DuplicateOperationId {op_id_winner!r} on the rejected duplicate, got {dup_op_id!r}"
        )
        # message varies: real AWS collapses both identical creates onto one OperationId, so this
        # branch's DuplicateRequest message is not known.
    else:
        # Both calls were treated as the identical retried request: both must resolve to
        # the very same operation (fully idempotent), never to two distinct namespaces.
        assert oks[0]["OperationId"] == oks[1]["OperationId"], (
            f"expected both concurrent identical-CreatorRequestId creates to collapse onto "
            f"the same OperationId, got {oks[0]['OperationId']!r} and {oks[1]['OperationId']!r}"
        )

    op_winner = _wait_operation(ctx, op_id_winner)
    assert op_winner["Status"] == "SUCCESS", f"winning create ended in {op_winner['Status']}: {op_winner.get('ErrorMessage')}"
    ns_id = op_winner["Targets"]["NAMESPACE"]

    # Effect absent: exactly one namespace exists under `name`, never two.
    listed = sd.list_namespaces(Filters=[{"Name": "NAME", "Values": [name], "Condition": "EQ"}])["Namespaces"]
    assert len(listed) == 1, f"expected exactly 1 namespace named {name!r}, got {listed}"
    assert listed[0]["Id"] == ns_id, f"expected listed namespace id {ns_id!r}, got {listed[0]['Id']!r}"


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


def _create_vpc(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.create_vpc(
        CidrBlock="10.47.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )
    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _delete_namespace_of_operation(ctx, operation_id: str) -> None:
    op = _wait_operation(ctx, operation_id)
    if op["Status"] == "SUCCESS":
        _safe_delete_namespace(ctx, op["Targets"]["NAMESPACE"])


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
