"""set-security-groups-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-security-groups-round-trip"
GROUP = "control-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetSecurityGroups replaces an ALB's security groups and DescribeLoadBalancers reflects
    the new set exactly."""
    net = _vpc_and_subnets(ctx)
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    arn = lb["LoadBalancerArn"]

    sg_name = ctx.unique_name("sim2real-elbv2-sg-")
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real elbv2 behavioral check",
        VpcId=net["vpc_id"],
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}
        ],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))
    # Ensure the load balancer (which pins the security group) is torn down before we try to
    # delete the security group itself: register a second LB-delete cleanup after the SG's,
    # so LIFO teardown detaches the SG first.
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))

    described_before = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    initial_sgs = described_before["SecurityGroups"]
    assert sg_id not in initial_sgs, (
        f"security group {sg_id} was just created and should not already be attached to a "
        f"fresh load balancer, but SecurityGroups reported {initial_sgs}"
    )

    elbv2.set_security_groups(LoadBalancerArn=arn, SecurityGroups=[sg_id])

    described_after = elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
    assert described_after["SecurityGroups"] == [sg_id], (
        f"expected SecurityGroups == [{sg_id!r}] after SetSecurityGroups, got "
        f"{described_after['SecurityGroups']!r}"
    )


# ===== helpers =====
# Not-found codes a teardown treats as already deleted; an in-use target group is retried.
_GONE = frozenset({
    "ListenerNotFound", "RuleNotFound", "TargetGroupNotFound", "LoadBalancerNotFound",
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
})


def _safe(fn):
    """Run one teardown call: a resource already gone is fine; one still held by a deleting load
    balancer (ResourceInUse) is retried every 2 s for up to 180 s; any other error raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _vpc_and_subnets(ctx):
    """Create-or-adopt: reuse any existing VPC with subnets in >=2 AZs (a fresh account may have
    no default VPC at all), else provision a minimal VPC+subnets of our own."""
    ec2 = ctx.client("ec2")
    reused = _reusable_vpc(ec2, ctx=ctx)
    if reused:
        return reused

    vpc_id = ec2.create_vpc(
        CidrBlock="10.98.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    if len(azs) < 2:
        raise AssertionError("fewer than 2 available availability zones in this region")
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.98.{i}.0/24",
            AvailabilityZone=az["ZoneName"],
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-elbv2-subnet-")}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _reusable_vpc(ec2, *, ctx):
    vpcs = sorted(ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"], key=lambda v: not v.get("IsDefault", False))
    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return {"vpc_id": vpc_id, "subnet_ids": list(by_az.values())[:2]}
    return None


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application")
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


# A load balancer or instance in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation.
# Teardown waits (bounded) for the ENIs, retries DependencyViolation in one window shared by the
# check's network deletes, then raises naming any ENIs still attached. Teardown-only: run() never calls this.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
