"""enable-availability-zones-on-a-vpc-load-balancer-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-availability-zones-on-a-vpc-load-balancer-rejected"
GROUP = 'rejection'
SERVICES = ['elb']

# ===== helpers =====
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _teardown(fn, *gone_codes):
    """Run one teardown call; only the resource's not-found codes count as already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in gone_codes:
            raise


def _error(fn):
    """The AWS error code and message `fn` raises; raises if the call succeeds, so accepting
    input AWS rejects is reported as such rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"the call real AWS rejects SUCCEEDED here, returning {str(result)[:300]!r}"
    )


def _internal_network(ctx, n=2):
    """Own VPC and one subnet per availability zone — never the default VPC. That is not only the
    self-containment rule here: the rejection this check grades is specifically about a
    NON-default VPC, so borrowing the account's default VPC would grade the opposite case."""
    ec2 = ctx.client("ec2")
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= n, f"{ctx.region} has {len(azs)} available zones {azs!r}, need {n}"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)
    is_default = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["IsDefault"]
    assert is_default is False, (
        f"the VPC this check created reports IsDefault={is_default!r}; the rejection it grades is "
        f"specific to a non-default VPC"
    )
    subnet_ids = []
    for i, az in enumerate(azs[:n]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.88.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": list(_TAGS)}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _drop_subnet(s=subnet_id):
            _teardown(lambda: _delete_net(ec2, "delete_subnet", SubnetId=s), "InvalidSubnetID.NotFound")

        ctx.on_cleanup(_drop_subnet)
    return vpc_id, subnet_ids, azs[:n]


def _sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real classic-elb control-plane check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        _teardown(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound")

    ctx.on_cleanup(_drop_sg)
    return sg_id


def _create_classic_lb(ctx, subnet_ids, sg_id):
    """Billable resource: the waited teardown is registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elb")
    lb_name = ctx.unique_name("sim2real-clb-")  # 25 chars; the API ceiling is 32
    elb.create_load_balancer(
        LoadBalancerName=lb_name,
        Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80,
                    "InstanceProtocol": "HTTP", "InstancePort": 80}],
        Subnets=list(subnet_ids), SecurityGroups=[sg_id], Scheme="internal",
        Tags=[{"Key": "sim2real", "Value": CHECK[:64]}],
    )

    def _drop_lb():
        _teardown(lambda: elb.delete_load_balancer(LoadBalancerName=lb_name), "LoadBalancerNotFound")
        # DeleteLoadBalancer returns before the ENIs are released: poll the name out of Describe
        # before the network deletes behind this one run.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.describe_load_balancers(LoadBalancerNames=[lb_name])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"load balancer {lb_name} still described 60 s after DeleteLoadBalancer")
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb_name


def _placement(ctx, lb_name):
    described = ctx.client("elb").describe_load_balancers(
        LoadBalancerNames=[lb_name])["LoadBalancerDescriptions"][0]
    return sorted(described["AvailabilityZones"]), sorted(described["Subnets"])


# ===== end helpers =====


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """EnableAvailabilityZonesForLoadBalancer is rejected with ValidationError for a load balancer in a
    non-default VPC and changes nothing, while AttachLoadBalancerToSubnets adds the same zone and
    its subnet: a VPC load balancer's zones are owned by its subnets."""
    elb = ctx.client("elb")
    vpc_id, subnet_ids, azs = _internal_network(ctx)
    sg_id = _sg(ctx, vpc_id)
    # Created in ONE zone, so the second zone is genuinely absent and can be added.
    lb_name = _create_classic_lb(ctx, subnet_ids[:1], sg_id)
    before_azs, before_subnets = _placement(ctx, lb_name)
    assert before_azs == [azs[0]] and before_subnets == [subnet_ids[0]], (
        f"the load balancer was placed in zones {before_azs!r} / subnets {before_subnets!r}, "
        f"expected exactly {[azs[0]]!r} / {[subnet_ids[0]]!r}"
    )

    code, message = _error(lambda: elb.enable_availability_zones_for_load_balancer(
        LoadBalancerName=lb_name, AvailabilityZones=[azs[1]]))
    assert code == "ValidationError", (
        f"enabling availability zone {azs[1]!r} on a VPC load balancer failed with {code!r}, "
        f"expected ValidationError"
    )
    expected = "You cannot enable Availability Zones for ELBs in a non default VPC"
    assert message == expected, (
        f"enabling availability zone {azs[1]!r} on a VPC load balancer failed with message "
        f"{message!r}, expected {expected!r}"
    )

    # EFFECT ABSENT: the refused call added neither the zone nor a subnet.
    after_azs, after_subnets = _placement(ctx, lb_name)
    assert (after_azs, after_subnets) == (before_azs, before_subnets), (
        f"after the refused EnableAvailabilityZones the load balancer reports zones "
        f"{after_azs!r} / subnets {after_subnets!r}, expected the unchanged {before_azs!r} / "
        f"{before_subnets!r}"
    )

    # POSITIVE CONTROL: the operation that DOES own zone membership in a VPC adds the same zone.
    attached = sorted(elb.attach_load_balancer_to_subnets(
        LoadBalancerName=lb_name, Subnets=[subnet_ids[1]])["Subnets"])
    assert attached == sorted(subnet_ids), (
        f"AttachLoadBalancerToSubnets returned subnets {attached!r}, expected both "
        f"{sorted(subnet_ids)!r}"
    )
    final_azs, final_subnets = _placement(ctx, lb_name)
    assert final_azs == sorted(azs), (
        f"after attaching the second subnet the load balancer reports zones {final_azs!r}, "
        f"expected {sorted(azs)!r} — the zone the refusal named is reachable, just not that way"
    )
    assert final_subnets == sorted(subnet_ids), (
        f"after attaching, the load balancer reports subnets {final_subnets!r}, expected "
        f"{sorted(subnet_ids)!r}"
    )


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
