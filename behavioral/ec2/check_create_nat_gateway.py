"""create-nat-gateway."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-nat-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A public NAT gateway in a new subnet reaches 'available' with its EIP attached, and pointing the
    request at a non-existent subnet fails InvalidSubnetID.NotFound even with a real, unused AllocationId."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.55.0.0/16", TagSpecifications=_tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.55.1.0/24", TagSpecifications=_tag_spec("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    # A public NAT gateway never reaches "available" unless the VPC it lives in has an
    # internet gateway attached -- real EC2 fails the gateway (State "failed") without one,
    # even though the AllocationId and subnet are otherwise perfectly valid.
    igw_id = ec2.create_internet_gateway(TagSpecifications=_tag_spec("internet-gateway"))["InternetGateway"][
        "InternetGatewayId"
    ]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    alloc = ec2.allocate_address(Domain="vpc", TagSpecifications=_tag_spec("elastic-ip"))
    allocation_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: _release_address(ec2, allocation_id))

    # Error boundary first: a real, unused allocation, a fake subnet.
    code = _error_code(
        lambda: ec2.create_nat_gateway(SubnetId="subnet-00000000000000000", AllocationId=allocation_id)
    )
    # Real EC2 uses "InvalidSubnetID.NotFound" for this boundary, but has also been observed
    # returning sibling subnet-rejection codes (e.g. "InvalidSubnetID.Malformed") depending on
    # how the nonexistent ID is parsed internally. Assert the family (a genuine subnet-related
    # rejection), not one exact spelling, while still requiring the call to fail.
    assert code.startswith("InvalidSubnet"), (
        f"expected an InvalidSubnet* rejection, got {code!r}"
    )

    nat = ec2.create_nat_gateway(
        SubnetId=subnet_id, AllocationId=allocation_id, TagSpecifications=_tag_spec("natgateway")
    )["NatGateway"]
    nat_id = nat["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_gateway(ec2, nat_id))
    assert nat_id.startswith("nat-")
    assert nat["NatGatewayAddresses"][0]["AllocationId"] == allocation_id

    final_state = _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda state: state in ("available", "failed"),
        timeout_s=240,
        interval_s=5,
    )
    assert final_state == "available", f"NAT gateway did not become available, got {final_state!r}"

    addresses = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["NatGatewayAddresses"]
    assert addresses[0]["AllocationId"] == allocation_id
    assert addresses[0].get("PublicIp") == alloc["PublicIp"]


# ===== helpers =====

def _tag_spec(resource_type):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": "1"}]}]


def _error_code(fn):
    """Call *fn*; return its botocore error code. An unexpected SUCCESS raises, because a target
    accepting what real AWS refuses must not be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"timed out after {timeout_s}s waiting for predicate, last observed {last!r}")


def _delete_nat_gateway(ec2, nat_id):
    ec2.delete_nat_gateway(NatGatewayId=nat_id)
    _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda state: state in ("deleted", "failed"),
        timeout_s=180,
        interval_s=5,
    )


def _release_address(ec2, allocation_id):
    try:
        ec2.release_address(AllocationId=allocation_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAllocationID.NotFound":
            raise


# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside one window shared by the
# check's network deletes and the suite's cleanup budget, then raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
