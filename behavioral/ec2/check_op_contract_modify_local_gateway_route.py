"""op-contract-modify-local-gateway-route."""
from __future__ import annotations

import ipaddress

from behavioral_harness import tags

CHECK = "op-contract-modify-local-gateway-route"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyLocalGatewayRoute rejects a local gateway route table id that does not exist with
    InvalidLocalGatewayRouteTableID.NotFound and its exact message, and the table is not listed."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "modify_local_gateway_route"):
        raise AssertionError("botocore in this environment lacks ModifyLocalGatewayRoute")

    name = ctx.unique_name("sim2real-lgw-route-unreachable-")
    tags_kv = [{"Key": "Name", "Value": name}]

    # The target (NetworkInterfaceId) is validated before the LocalGatewayRouteTableId, so a made-up
    # ENI id would surface InvalidNetworkInterfaceID.NotFound instead of exercising the route-table
    # boundary this check is about. Use a real ENI as the target so the only invalid reference in
    # the request is the local gateway route table id. Reuse an existing VPC (default, or any)
    # rather than depending on an ambient default VPC existing *or* minting a fresh one: a real
    # account's per-region VPC limit is easily exhausted by many behavioral checks each allocating
    # their own.
    vpc_id = _existing_vpc_id(ec2, ctx=ctx)
    cidr = _free_subnet_cidr(ec2, vpc_id, prefix_len=28)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=cidr, TagSpecifications=[{"ResourceType": "subnet", "Tags": tags_kv}]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    eni = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[{"ResourceType": "network-interface", "Tags": tags_kv}]
    )["NetworkInterface"]
    eni_id = eni["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    fake_route_table_id = "lgw-rtb-00000000000000000"
    code, message = _error(
        lambda: ec2.modify_local_gateway_route(
            LocalGatewayRouteTableId=fake_route_table_id,
            DestinationCidrBlock="10.250.0.0/24",
            NetworkInterfaceId=eni_id,
        )
    )
    assert code == "InvalidLocalGatewayRouteTableID.NotFound", (
        f"expected InvalidLocalGatewayRouteTableID.NotFound, got {code}"
    )
    assert message == "The LocalGateway Route Table ID 'lgw-rtb-00000000000000000' does not exist", message

    # Independent read, through a different operation than the one that was rejected: the route
    # table id was never real, so it must not appear when EC2 is asked to describe it either.
    described = ec2.describe_local_gateway_route_tables(
        LocalGatewayRouteTableIds=[fake_route_table_id]
    )["LocalGatewayRouteTables"]
    assert described == [], (
        f"expected no local gateway route table for {fake_route_table_id!r}, got {described}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _existing_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        return vpcs[0]["VpcId"]
    raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")


def _free_subnet_cidr(ec2, vpc_id, prefix_len=28):
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    associations = [
        a for a in vpc.get("CidrBlockAssociationSet", [])
        if a.get("CidrBlockState", {}).get("State") == "associated"
    ]
    vpc_nets = [ipaddress.ip_network(a["CidrBlock"]) for a in associations] or [
        ipaddress.ip_network(vpc["CidrBlock"])
    ]
    existing = [
        ipaddress.ip_network(s["CidrBlock"])
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]
    for vpc_net in vpc_nets:
        if vpc_net.prefixlen > prefix_len:
            continue
        for candidate in vpc_net.subnets(new_prefix=prefix_len):
            if not any(candidate.overlaps(e) for e in existing):
                return str(candidate)
    raise AssertionError(f"no free /{prefix_len} CIDR block found in VPC {vpc_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
