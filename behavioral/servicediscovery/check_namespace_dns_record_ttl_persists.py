"""namespace-dns-record-ttl-persists."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "namespace-dns-record-ttl-persists"
GROUP = "visibility-timeout-ttl"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom DNS record TTL set on a service created under a private DNS namespace
    is preserved exactly (no rounding/coercion) across repeated GetService reads."""
    vpc_id = _create_vpc(ctx)

    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_private_dns_namespace(ctx, ns_name, vpc_id)

    svc_name = ctx.unique_name("sim2real-behav-svc-")
    sd = ctx.client("servicediscovery")
    custom_ttl = 42
    service = sd.create_service(
        Name=svc_name,
        NamespaceId=namespace_id,
        DnsConfig={"DnsRecords": [{"Type": "A", "TTL": custom_ttl}]},
    )["Service"]
    service_id = service["Id"]
    ctx.on_cleanup(lambda: _safe_delete_service(sd, service_id))

    records = service["DnsConfig"]["DnsRecords"]
    assert len(records) == 1, f"expected 1 DNS record on create, got {len(records)}: {records}"
    assert records[0]["Type"] == "A", f"expected record type A on create, got {records[0]['Type']!r}"
    assert records[0]["TTL"] == custom_ttl, f"create response TTL={records[0]['TTL']!r}, expected {custom_ttl}"

    # Read it back independently and repeatedly (freeze detector): every GetService call
    # must return the exact same int, not just the first -- rules out a value that only
    # looks right on the read immediately following the write.
    for attempt in range(3):
        fetched = sd.get_service(Id=service_id)["Service"]
        fetched_records = fetched["DnsConfig"]["DnsRecords"]
        assert len(fetched_records) == 1, (
            f"read {attempt}: expected 1 DNS record, got {len(fetched_records)}: {fetched_records}"
        )
        assert fetched_records[0]["Type"] == "A", (
            f"read {attempt}: expected record type A, got {fetched_records[0]['Type']!r}"
        )
        ttl = fetched_records[0]["TTL"]
        assert ttl == custom_ttl, f"read {attempt}: TTL drifted: expected {custom_ttl}, got {ttl!r}"
        assert isinstance(ttl, int), f"read {attempt}: TTL round-tripped as non-integer type {type(ttl)!r}: {ttl!r}"


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


def _create_vpc(ctx) -> str:
    # The check owns the VPC its private DNS namespace attaches to, so it never depends on
    # an account default VPC it did not create.
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.216.0.0/24",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    deadline = time.monotonic() + 30.0
    while True:
        state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if state == "available":
            return vpc_id
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPC {vpc_id} did not reach available within 30s (last state={state})")
        time.sleep(1)


def _create_private_dns_namespace(ctx, name: str, vpc_id: str) -> str:
    sd = ctx.client("servicediscovery")
    op_id = sd.create_private_dns_namespace(Name=name, Vpc=vpc_id)["OperationId"]
    # Route 53 private hosted zone provisioning; this can take a few minutes.
    op = _wait_operation(ctx, op_id, timeout_s=300.0, interval_s=5.0)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op}"
    namespace_id = op["Targets"]["NAMESPACE"]

    def _cleanup():
        try:
            del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
            _wait_operation(ctx, del_op_id, timeout_s=300.0, interval_s=5.0)
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
