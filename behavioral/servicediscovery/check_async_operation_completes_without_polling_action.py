"""async-operation-completes-without-polling-action."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "async-operation-completes-without-polling-action"
GROUP = "server-side"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePrivateDnsNamespace's operation is first read as SUBMITTED or PENDING and then reaches
    SUCCESS with Type CREATE_NAMESPACE through GetOperation polls alone, and the DNS_PRIVATE namespace
    then exists under its name: the provisioning really runs server-side and asynchronously."""
    vpc_id = _default_vpc_id(ctx)
    sd = ctx.client("servicediscovery")

    name = ctx.unique_name("sim2real-behav-ns-")
    op_id = sd.create_private_dns_namespace(
        Name=name,
        Vpc=vpc_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["OperationId"]

    observed_statuses: list[str] = []
    deadline = time.monotonic() + 300.0
    op: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=op_id)["Operation"]
        observed_statuses.append(op["Status"])
        if op["Status"] in ("SUCCESS", "FAIL"):
            break
        time.sleep(5.0)

    assert op is not None, f"operation {op_id} produced no GetOperation response within 300s"
    assert op["Status"] == "SUCCESS", f"namespace create operation did not succeed purely server-side: {op}"
    assert op["Type"] == "CREATE_NAMESPACE", f"expected Type=CREATE_NAMESPACE, got {op['Type']}"
    namespace_id = op["Targets"]["NAMESPACE"]

    def _cleanup():
        try:
            del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
            _wait_operation(ctx, del_op_id, timeout_s=300.0, interval_s=5.0)
        except sd.exceptions.NamespaceNotFound:
            pass

    ctx.on_cleanup(_cleanup)

    # The namespace itself must now exist -- proof the async work actually completed,
    # not merely that the operation record flipped a status field.
    ns = sd.get_namespace(Id=namespace_id)["Namespace"]
    assert ns["Name"] == name, f"expected namespace Name={name!r}, got {ns['Name']!r}"
    assert ns["Type"] == "DNS_PRIVATE", f"expected Type=DNS_PRIVATE, got {ns['Type']!r}"
    # The only mutating call is the single CreatePrivateDnsNamespace; every
    # subsequent call in this loop is a read-only GetOperation poll. The
    # transition must actually have been observed non-terminal at least once --
    # Route 53 hosted-zone provisioning is not instantaneous, so an operation that
    # reports SUCCESS on the very first poll never proved anything asynchronous.
    assert observed_statuses[0] in ("SUBMITTED", "PENDING"), (
        f"expected the operation to still be in-flight on the first poll (proving "
        f"server-side async provisioning, not an instantaneous echo); observed {observed_statuses}"
    )


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
    if vpcs:
        return vpcs[0]["VpcId"]

    # A freshly provisioned account may have no shared network -- create-or-adopt
    # rather than depend on ambient state.
    created = ec2.create_vpc(
        CidrBlock="10.219.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = created["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
