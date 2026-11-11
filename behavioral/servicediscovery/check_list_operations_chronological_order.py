"""list-operations-chronological-order."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-operations-chronological-order"
GROUP = "ordering"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A full ListOperations pagination pass contains every submitted operation exactly once, and a
    second pass returns them in the identical relative order."""
    vpc_id = _default_vpc_id(ctx)
    sd = ctx.client("servicediscovery")

    op_ids: list[str] = []
    for _ in range(3):
        name = ctx.unique_name("sim2real-behav-ns-")
        op_id = sd.create_private_dns_namespace(
            Name=name, Vpc=vpc_id, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
        )["OperationId"]
        op_ids.append(op_id)

        def _cleanup(op_id=op_id):
            op = _wait_operation(ctx, op_id, timeout_s=300.0, interval_s=5.0)
            if op["Status"] != "SUCCESS":
                return
            namespace_id = op["Targets"]["NAMESPACE"]
            try:
                del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
                _wait_operation(ctx, del_op_id, timeout_s=300.0, interval_s=5.0)
            except sd.exceptions.NamespaceNotFound:
                pass

        ctx.on_cleanup(_cleanup)

    op_id_set = set(op_ids)
    filters = [{"Name": "TYPE", "Condition": "EQ", "Values": ["CREATE_NAMESPACE"]}]

    # ListOperations can transiently lag operation submission (eventual consistency);
    # poll a full pagination pass until every submitted op shows up before comparing
    # ordering, rather than treating the first pass as authoritative.
    pass_a = _poll_full_pagination(sd, filters, op_id_set, page_size=1)
    pass_b = _paginate_operation_ids(sd, filters, page_size=1)

    assert len(pass_a) == len(set(pass_a)), "duplicate operation id within one ListOperations pagination pass"
    assert op_id_set.issubset(set(pass_a)), f"missing submitted operations from ListOperations: {op_id_set - set(pass_a)}"


    order_a = [oid for oid in pass_a if oid in op_id_set]
    order_b = [oid for oid in pass_b if oid in op_id_set]
    assert order_a == order_b, f"ListOperations pagination order not stable across passes: {order_a} != {order_b}"
    assert len(order_a) == len(op_ids), "some submitted operations missing from the ordered subset"


def _wait_operation(ctx, operation_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> dict[str, Any]:
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    op: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} did not reach a terminal state within {timeout_s}s (last={op})")


def _default_vpc_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to create private DNS "
            "namespaces for -- would close by creating/selecting any VPC to pass as Vpc"
        )
    return vpcs[0]["VpcId"]


def _paginate_operation_ids(sd, filters: list[dict[str, Any]], page_size: int) -> list[str]:
    ids: list[str] = []
    next_token = None
    while True:
        kwargs: dict[str, Any] = {"Filters": filters, "MaxResults": page_size}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = sd.list_operations(**kwargs)
        ids.extend(op["Id"] for op in resp.get("Operations", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return ids


def _poll_full_pagination(
    sd, filters: list[dict[str, Any]], required_ids: set[str], page_size: int,
    timeout_s: float = 90.0, interval_s: float = 5.0,
) -> list[str]:
    deadline = time.monotonic() + timeout_s
    last: list[str] = []
    while time.monotonic() < deadline:
        last = _paginate_operation_ids(sd, filters, page_size)
        if required_ids.issubset(set(last)):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"ListOperations did not surface all {len(required_ids)} submitted operations "
        f"within {timeout_s}s (last pagination pass had {len(last)} matching ops, "
        f"missing={required_ids - set(last)})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
