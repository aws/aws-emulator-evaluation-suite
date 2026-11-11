"""dns-record-ttl-numeric-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "dns-record-ttl-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A near-int32-max SOA TTL set in CreatePrivateDnsNamespace.Properties round-trips with exact numeric precision."""
    sd = ctx.client("servicediscovery")
    vpc_id = _resolve_vpc_id(ctx)

    ns_name = ctx.unique_name("simparity-sd-") + ".local"
    ttl_value = 2147483647  # RecordTTL max (int32 max) -- exercises exact large-integer round-trip

    resp = sd.create_private_dns_namespace(
        Name=ns_name,
        Vpc=vpc_id,
        Properties={"DnsProperties": {"SOA": {"TTL": ttl_value}}},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    op = _wait_operation(sd, resp["OperationId"])
    ns_id = op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _delete_namespace_best_effort(sd, ns_id))

    namespace = sd.get_namespace(Id=ns_id)["Namespace"]
    got_ttl = namespace["Properties"]["DnsProperties"]["SOA"]["TTL"]

    assert got_ttl == ttl_value, f"SOA TTL round-tripped as {got_ttl!r}, expected exact {ttl_value!r}"
    assert isinstance(got_ttl, int), f"SOA TTL round-tripped as non-integer type {type(got_ttl)!r}"


def _resolve_vpc_id(ctx):
    """Adopt the run's shared network when present; otherwise create-and-clean-up one, so a
    freshly provisioned account with no shared network still runs this check."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if vpcs:
        return vpcs[0]["VpcId"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [
                    {"Key": "sim2real-check", "Value": CHECK},
                    {"Key": "Name", "Value": ctx.unique_name("simparity-sd-vpc-")},
                ],
            }
        ],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _wait_operation(sd, operation_id, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        status = op["Status"]
        if status == "SUCCESS":
            return op
        if status == "FAIL":
            raise AssertionError(
                f"operation {operation_id} failed: {op.get('ErrorCode')} {op.get('ErrorMessage')}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"operation {operation_id} stuck in {status} after {timeout_s}s")
        time.sleep(interval_s)


def _delete_namespace_best_effort(sd, namespace_id):
    from botocore.exceptions import ClientError

    try:
        op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
        _wait_operation(sd, op_id, timeout_s=180.0)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NamespaceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
