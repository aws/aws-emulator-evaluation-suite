"""nat-gateway-create-available-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _cleanup_igw(ec2, igw_id, vpc_id):
    try:
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise
    try:
        _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


def _delete_nat_and_wait(ec2, nat_id):
    """Delete a NAT gateway and wait for 'deleted'.

    Until then it keeps a managed ENI in the subnet, which blocks the subnet/VPC deletes."""
    try:
        ec2.delete_nat_gateway(NatGatewayId=nat_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NatGatewayNotFound":
            raise
        return
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NatGatewayNotFound":
                raise
            return
        if state == "deleted":
            return
        time.sleep(5)


def _wait_nat_state(ec2, nat_id, targets, timeout_s):
    """Poll until the NAT gateway reaches one of ``targets``; return the last observed state."""
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        # EC2 stops returning a gateway once it is reaped; treat that as `deleted`.
        try:
            gws = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NatGatewayNotFound":
                return "deleted"
            raise
        if not gws:
            return "deleted"
        state = gws[0]["State"]
        if state in targets:
            return state
        time.sleep(5)
    return state


def _release_eip(ec2, alloc_id):
    """Best-effort teardown: disassociate (if bound) then release the EIP."""
    try:
        addr = ec2.describe_addresses(AllocationIds=[alloc_id])["Addresses"][0]
        if addr.get("AssociationId"):
            ec2.disassociate_address(AssociationId=addr["AssociationId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAllocationID.NotFound",
            "InvalidAssociationID.NotFound",
        ):
            raise
    try:
        ec2.release_address(AllocationId=alloc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAllocationID.NotFound":
            raise

CHECK = "nat-gateway-create-available-delete-lifecycle"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNatGateway reaches available, DeleteNatGateway ends in deleted."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.82.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.82.1.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    # A public NAT gateway requires an internet gateway on the VPC, otherwise it
    # transitions pending->failed with Gateway.NotAttached.
    igw_id = ec2.create_internet_gateway(TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _cleanup_igw(ec2, igw_id, vpc_id))

    alloc_id = ec2.allocate_address(Domain="vpc", TagSpecifications=[{"ResourceType": "elastic-ip", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["AllocationId"]
    ctx.on_cleanup(lambda: _release_eip(ec2, alloc_id))

    nat = ec2.create_nat_gateway(SubnetId=subnet_id, AllocationId=alloc_id, TagSpecifications=[{"ResourceType": "natgateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    nat_id = nat["NatGateway"]["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_and_wait(ec2, nat_id))
    assert nat["NatGateway"]["State"] == "pending", (
        f"expected new NAT gateway to start pending, got {nat['NatGateway']['State']}"
    )

    # NAT provisioning usually takes 2-3 min but occasionally exceeds 300s.
    state = _wait_nat_state(ec2, nat_id, ("available", "failed"), 420)
    assert state == "available", f"expected NAT gateway available, got {state}"

    ec2.delete_nat_gateway(NatGatewayId=nat_id)
    state = _wait_nat_state(ec2, nat_id, ("deleted",), 300)
    assert state == "deleted", f"expected NAT gateway deleted after DeleteNatGateway, got {state}"


# AWS-managed ENIs (e.g. a NAT gateway's) leave a subnet/VPC asynchronously after their owner is
# deleted, so an immediate delete fails with DependencyViolation. Teardown waits (bounded, one window
# shared by all of a check's network deletes) for them, then raises naming the ENIs still attached.
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
