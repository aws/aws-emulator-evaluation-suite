"""route-table-local-route-and-main-association-immutable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route-table-local-route-and-main-association-immutable"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

ERR_INVALID_PARAM = 'InvalidParameterValue'
VPC_CIDR = '10.140.0.0/16'
SUBNET_CIDR = '10.140.1.0/24'


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _wait_vpc_available(ec2, vpc_id, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if last == "available":
            return
        time.sleep(2)
    raise AssertionError(f"vpc {vpc_id} never reached available in {timeout_s}s (last {last!r})")


def _route_tables(ec2, vpc_id):
    return ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["RouteTables"]


def _main_table(ec2, vpc_id):
    for rt in _route_tables(ec2, vpc_id):
        for a in rt.get("Associations", []):
            if a.get("Main"):
                return rt, a
    raise AssertionError(f"vpc {vpc_id} has no main route table association")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRoute on the VPC's implicit `local` route and DisassociateRouteTable on the main
    association are both rejected and leave the table unchanged; on a custom table both succeed.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": "1"}]

    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=SUBNET_CIDR,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    # --- the VPC ships with a main route table carrying exactly one 'local' route ---
    main_rt, main_assoc = _main_table(ec2, vpc_id)
    main_rt_id, main_assoc_id = main_rt["RouteTableId"], main_assoc["RouteTableAssociationId"]
    local = [r for r in main_rt["Routes"] if r.get("GatewayId") == "local"]
    assert len(local) == 1, f"expected exactly one local route on {main_rt_id}, got {main_rt['Routes']}"
    assert local[0]["DestinationCidrBlock"] == VPC_CIDR, (
        f"local route must target the VPC CIDR {VPC_CIDR}, got {local[0]['DestinationCidrBlock']}"
    )
    assert local[0]["State"] == "active", f"local route state {local[0]['State']!r}, expected active"
    assert local[0].get("Origin") == "CreateRouteTable", (
        f"local route Origin must be CreateRouteTable, got {local[0].get('Origin')!r}"
    )

    # --- negative 1: the local route cannot be deleted ---
    try:
        ec2.delete_route(RouteTableId=main_rt_id, DestinationCidrBlock=VPC_CIDR)
    except ClientError as exc:
        assert _code(exc) == ERR_INVALID_PARAM, (
            f"expected {ERR_INVALID_PARAM} deleting the local route, got {_code(exc)}"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == f"cannot remove local route {VPC_CIDR} in route table {main_rt_id}", message
    else:
        raise AssertionError(f"DeleteRoute on the local route of {main_rt_id} must be rejected, it succeeded")
    after = ec2.describe_route_tables(RouteTableIds=[main_rt_id])["RouteTables"][0]
    assert [r for r in after["Routes"] if r.get("GatewayId") == "local"], (
        f"rejected DeleteRoute must leave the local route intact, routes now {after['Routes']}"
    )

    # --- negative 2: the main association cannot be disassociated ---
    try:
        ec2.disassociate_route_table(AssociationId=main_assoc_id)
    except ClientError as exc:
        assert _code(exc) == ERR_INVALID_PARAM, (
            f"expected {ERR_INVALID_PARAM} disassociating main association {main_assoc_id}, got {_code(exc)}"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == f"cannot disassociate the main route table association {main_assoc_id}", message
    else:
        raise AssertionError(
            f"DisassociateRouteTable on the main association {main_assoc_id} must be rejected, it succeeded"
        )
    _, still_main = _main_table(ec2, vpc_id)
    assert still_main["RouteTableAssociationId"] == main_assoc_id, (
        f"rejected disassociate must leave the main association {main_assoc_id} in place, "
        f"got {still_main['RouteTableAssociationId']}"
    )

    # --- control: on a CUSTOM route table both operations succeed ---
    custom_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": tag}],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=custom_id))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tag}],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))

    ec2.create_route(RouteTableId=custom_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    custom_assoc_id = ec2.associate_route_table(RouteTableId=custom_id, SubnetId=subnet_id)["AssociationId"]

    ec2.delete_route(RouteTableId=custom_id, DestinationCidrBlock="0.0.0.0/0")
    custom = ec2.describe_route_tables(RouteTableIds=[custom_id])["RouteTables"][0]
    assert not [r for r in custom["Routes"] if r.get("DestinationCidrBlock") == "0.0.0.0/0"], (
        f"DeleteRoute on a custom table must remove the route, routes now {custom['Routes']}"
    )
    ec2.disassociate_route_table(AssociationId=custom_assoc_id)
    custom = ec2.describe_route_tables(RouteTableIds=[custom_id])["RouteTables"][0]
    assert not [
        a for a in custom.get("Associations", []) if a.get("SubnetId") == subnet_id
    ], f"custom association must be removable, associations now {custom.get('Associations')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
