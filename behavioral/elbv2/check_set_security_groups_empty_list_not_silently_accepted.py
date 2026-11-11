"""set-security-groups-empty-list-not-silently-accepted."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "set-security-groups-empty-list-not-silently-accepted"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetSecurityGroups with an empty list on an internet-facing ALB fails with ValidationError
    "A security group must be specified" and the ALB keeps its security group; a non-empty list
    is accepted."""
    elbv2 = ctx.client("elbv2")
    lb_arn, sg_id = _create_alb(ctx)
    assert sg_id, "test requires a security group to exist in the VPC"

    # A valid list must succeed first, so the rejection below is specific to the empty list.
    control_resp = elbv2.set_security_groups(LoadBalancerArn=lb_arn, SecurityGroups=[sg_id])
    assert control_resp["SecurityGroupIds"] == [sg_id], (
        f"positive control failed: SetSecurityGroups([{sg_id!r}]) did not return that group, "
        f"got {control_resp['SecurityGroupIds']!r}"
    )
    control_lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert control_lb["SecurityGroups"] == [sg_id], (
        f"positive control failed: load balancer does not reflect a valid SetSecurityGroups "
        f"call, got {control_lb['SecurityGroups']!r}"
    )

    code, message = _error(lambda: elbv2.set_security_groups(LoadBalancerArn=lb_arn, SecurityGroups=[]))
    assert code == "ValidationError", f"expected the empty SecurityGroups list to be rejected, got {code}: {message}"
    assert message == "A security group must be specified", f"unexpected refusal message: {message!r}"
    lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    assert lb["SecurityGroups"] == [sg_id], (
        f"security groups changed despite a rejected SetSecurityGroups call: {lb['SecurityGroups']}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; a successful call is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _get_alb_network(ctx) -> tuple[str, list[str], str]:
    ec2 = ctx.client("ec2")
    vpc_id, subnet_ids = _own_public_vpc(ctx)
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-sgemp-"),
        Description="sim2real elbv2 set-security-groups subject",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_NET_TAGS)}],
    )["GroupId"]
    ctx.on_cleanup(_net_safe_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))
    return vpc_id, subnet_ids, sg_id


def _alb_name(ctx, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:32].rstrip("-")


def _create_alb(ctx) -> tuple[str, str | None]:
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids, sg_id = _get_alb_network(ctx)
    kwargs: dict[str, Any] = dict(
        Name=_alb_name(ctx, "sgemp"),
        Subnets=subnet_ids,
        Type="application",
        Scheme="internet-facing",
        SecurityGroups=[sg_id],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    lb = elbv2.create_load_balancer(**kwargs)["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    return lb_arn, sg_id



# ===== own network (self-contained) =====

_NET_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _net_safe_cleanup(fn):
    """Teardown-only tolerance. Never used on an assertion path."""
    from botocore.exceptions import ClientError as _ClientError

    def _wrapped():
        try:
            fn()
        except (_ClientError, OSError, KeyError, IndexError, AssertionError):
            return

    return _wrapped


def _own_public_vpc(ctx, cidr="10.172.0.0/16", n_subnets=2):
    """A VPC this check creates, with an internet gateway and public subnets in n distinct AZs."""
    ec2 = ctx.client("ec2")

    def _tagspec(kind):
        return {"ResourceType": kind, "Tags": list(_NET_TAGS)}

    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_net_safe_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= n_subnets, f"{ctx.region} exposes {len(azs)} available AZs, need {n_subnets}"

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tagspec("internet-gateway")])["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _net_safe_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))()
        _net_safe_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))()

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tagspec("route-table")])["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_net_safe_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rtb_id)))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    octets = cidr.split(".")
    subnet_ids = []
    for i, az in enumerate(azs[:n_subnets]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"{octets[0]}.{octets[1]}.{i}.0/24",
            AvailabilityZone=az, TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(_net_safe_cleanup(lambda s=sid: _delete_net(ec2, "delete_subnet", SubnetId=s)))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        assoc = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)["AssociationId"]
        ctx.on_cleanup(_net_safe_cleanup(lambda a=assoc: ec2.disassociate_route_table(AssociationId=a)))
    return vpc_id, subnet_ids


# Network deletes wait (bounded) for the ENIs a load balancer or function leaves behind, retrying
# DependencyViolation inside one shared window, and raise a final failure naming the ENIs.
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
