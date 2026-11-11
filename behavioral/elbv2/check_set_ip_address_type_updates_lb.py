"""set-ip-address-type-updates-lb."""
from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags

CHECK = "set-ip-address-type-updates-lb"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetIpAddressType changes the load balancer's IP address type, as DescribeLoadBalancers shows."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _create_dualstack_ready_vpc(ctx)
    sg_id = _default_sg(ctx, vpc_id)
    lb_arn = _create_internet_facing_alb(ctx, subnet_ids, [sg_id])

    initial = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert initial["IpAddressType"] == "ipv4", (
        f"expected freshly created ALB to report IpAddressType=ipv4, got {initial['IpAddressType']!r}"
    )

    set_resp = elbv2.set_ip_address_type(LoadBalancerArn=lb_arn, IpAddressType="dualstack")
    assert set_resp["IpAddressType"] == "dualstack", (
        f"expected SetIpAddressType(dualstack) response to echo dualstack, got {set_resp['IpAddressType']!r}"
    )

    described = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert described["IpAddressType"] == "dualstack", (
        f"expected DescribeLoadBalancers to reflect dualstack after SetIpAddressType, "
        f"got {described['IpAddressType']!r}"
    )

    reverted = elbv2.set_ip_address_type(LoadBalancerArn=lb_arn, IpAddressType="ipv4")
    assert reverted["IpAddressType"] == "ipv4", (
        f"expected SetIpAddressType(ipv4) response to echo ipv4, got {reverted['IpAddressType']!r}"
    )

    described_again = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert described_again["IpAddressType"] == "ipv4", (
        f"expected DescribeLoadBalancers to reflect ipv4 after reverting, "
        f"got {described_again['IpAddressType']!r}"
    )


def _tag_spec(ctx, resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-elbv2-{resource_type}-")}],
    }


def _create_dualstack_ready_vpc(ctx):
    """A dual-stack VPC the check owns: two subnets in two zones with an IPv6 /64 each, routed to its
    own internet gateway for 0.0.0.0/0 and ::/0; the teardown deletes all of it."""
    ec2 = ctx.client("ec2")
    teardown: dict = {}
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16", AmazonProvidedIpv6CidrBlock=True, TagSpecifications=[_tag_spec(ctx, "vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, teardown, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    ipv6_cidr = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        assoc = vpc.get("Ipv6CidrBlockAssociationSet", [])
        if assoc and assoc[0]["Ipv6CidrBlockState"]["State"] == "associated":
            ipv6_cidr = assoc[0]["Ipv6CidrBlock"]
            break
        time.sleep(2.0)
    if not ipv6_cidr:
        raise AssertionError("VPC did not receive an associated IPv6 CIDR block in time")

    igw_id = ec2.create_internet_gateway(TagSpecifications=[_tag_spec(ctx, "internet-gateway")])[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, teardown, "delete_internet_gateway", InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(
        ec2, teardown, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))

    rt_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "route-table")])[
        "RouteTable"
    ]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, teardown, "delete_route_table", RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    ec2.create_route(RouteTableId=rt_id, DestinationIpv6CidrBlock="::/0", GatewayId=igw_id)

    v6_subnets = list(ipaddress.ip_network(ipv6_cidr).subnets(new_prefix=64))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]

    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=az["ZoneName"],
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, teardown, "delete_subnet", SubnetId=sid))
        assoc_id = ec2.associate_subnet_cidr_block(SubnetId=subnet_id, Ipv6CidrBlock=str(v6_subnets[i]))[
            "Ipv6CidrBlockAssociation"]["AssociationId"]
        _wait_subnet_ipv6_associated(ec2, subnet_id, assoc_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        ec2.modify_subnet_attribute(SubnetId=subnet_id, AssignIpv6AddressOnCreation={"Value": True})
        ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)
        subnet_ids.append(subnet_id)

    return vpc_id, subnet_ids


def _wait_subnet_ipv6_associated(ec2, subnet_id, assoc_id, timeout_s=60.0):
    """AssignIpv6AddressOnCreation needs the subnet's IPv6 block associated, not still associating."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        sets = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0].get("Ipv6CidrBlockAssociationSet", [])
        if any(a["AssociationId"] == assoc_id and a["Ipv6CidrBlockState"]["State"] == "associated" for a in sets):
            return
        time.sleep(2.0)
    raise AssertionError(f"subnet {subnet_id} IPv6 CIDR block not associated within {timeout_s}s")


def _default_sg(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    return ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]


def _create_internet_facing_alb(ctx, subnet_ids, sg_ids) -> str:
    elbv2 = ctx.client("elbv2")
    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-alb-"), Subnets=subnet_ids, SecurityGroups=sg_ids,
        Scheme="internet-facing", Type="application", IpAddressType="ipv4",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_for_lb_active(ctx, lb_arn)
    return lb_arn


def _wait_for_lb_active(ctx, lb_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        code = lb["State"]["Code"]
        if code == "active":
            return lb
        if code == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State'].get('Reason')}")
        time.sleep(interval_s)
    raise AssertionError(f"load balancer did not reach active within {timeout_s}s")


# Load balancers delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry to the run's network deadline, then fail naming the ENIs left.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}


def _delete_net(client, teardown, op, **ident):
    from botocore.exceptions import ClientError as _ClientError

    # One deadline per run, started by the first network delete and held in the run's teardown dict.
    deadline = teardown.setdefault("deadline", time.monotonic() + _NET_TEARDOWN_S)
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(2)


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
