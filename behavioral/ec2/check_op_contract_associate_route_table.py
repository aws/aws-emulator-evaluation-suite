"""op-contract-associate-route-table."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-associate-route-table"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateRouteTable binds a route table to a subnet, causing traffic from that subnet
    to follow the route table's routes; a nonexistent route table id is rejected."""
    ec2 = ctx.client("ec2")
    vpc_id = _create_vpc(ec2, ctx, "10.214.0.0/16", ctx.unique_name("sim2real-artvpc-"))
    subnet_cidr = _pick_subnet_cidr(ec2, vpc_id)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        TagSpecifications=[_tag_spec("subnet", ctx.unique_name("sim2real-artsubnet-"))],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    main_rtb_id = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "association.main", "Values": ["true"]}]
    )["RouteTables"][0]["RouteTableId"]

    custom_rtb_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("route-table", ctx.unique_name("sim2real-rtb-"))],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=custom_rtb_id))

    resp = ec2.associate_route_table(RouteTableId=custom_rtb_id, SubnetId=subnet_id)
    assoc_id = resp["AssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))
    assert resp["AssociationState"]["State"] in ("associating", "associated"), (
        f"expected an associating/associated state, got {resp['AssociationState']}"
    )

    described = ec2.describe_route_tables(RouteTableIds=[custom_rtb_id])["RouteTables"][0]
    subnet_assocs = {a.get("SubnetId") for a in described["Associations"]}
    assert subnet_id in subnet_assocs, f"subnet association not reflected: {described['Associations']}"

    # The subnet no longer implicitly follows the main route table.
    main_rtb = ec2.describe_route_tables(RouteTableIds=[main_rtb_id])["RouteTables"][0]
    main_subnets = {a.get("SubnetId") for a in main_rtb["Associations"]}
    assert subnet_id not in main_subnets, (
        f"subnet {subnet_id} unexpectedly still implicitly associated with main route table {main_rtb_id}"
    )

    fake_rtb_id = "rtb-00000000000000000"
    code, message = _client_error(lambda: ec2.associate_route_table(RouteTableId=fake_rtb_id, SubnetId=subnet_id))
    assert code == "InvalidRouteTableID.NotFound", f"unexpected error code: {code}"
    expected = f"The routeTable ID '{fake_rtb_id}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc(ec2, ctx, cidr, name):
    # A dedicated VPC: the check never depends on a VPC the account already holds.
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(
        VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    return vpc_id


def _pick_subnet_cidr(ec2, vpc_id):
    """Return an unused /24 CIDR that actually lies within the given VPC's CIDR block(s),
    avoiding any subnets that already exist in that VPC."""
    import ipaddress

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    vpc_cidrs = [
        assoc["CidrBlock"]
        for assoc in vpc.get("CidrBlockAssociationSet", [])
        if assoc.get("CidrBlockState", {}).get("State") == "associated"
    ]
    if not vpc_cidrs:
        vpc_cidrs = [vpc["CidrBlock"]]

    existing = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    used = [ipaddress.ip_network(s["CidrBlock"]) for s in existing]

    for vpc_cidr in vpc_cidrs:
        network = ipaddress.ip_network(vpc_cidr)
        new_prefix = max(network.prefixlen, 24)
        for candidate in network.subnets(new_prefix=new_prefix):
            if not any(candidate.overlaps(u) for u in used):
                return str(candidate)
    raise RuntimeError(f"no available /24 subnet CIDR found within VPC {vpc_id}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
