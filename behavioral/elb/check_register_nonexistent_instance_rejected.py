"""register-nonexistent-instance-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-nonexistent-instance-rejected"
GROUP = 'registration'
SERVICES = ['elb']

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})


_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _clamp_name(name, maxlen=32):
    """Classic ELB names are <=32 chars and may not end in a hyphen."""
    return name[:maxlen].rstrip("-")


def _teardown(fn, *gone_codes):
    """Run one teardown call; only the resource's not-found codes count as already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in gone_codes:
            raise


_ELB_GONE = ("LoadBalancerNotFound", "ListenerNotFound", "PolicyNotFound", "InvalidInstance", "SubnetNotFound",
             "InvalidAssociationID.NotFound")


def _safe(fn):
    """A cleanup step DeleteLoadBalancer also covers: done once the load balancer or the item is gone."""
    return lambda: _teardown(fn, *_ELB_GONE)


def _retry_throttled(fn, attempts=5):
    delays = [3, 6, 12, 24, 30]
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(delays[min(i, len(delays) - 1)])
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _usable_azs(ctx, want="t3.micro", n=2):
    """AZ names that are BOTH available and really offer `want`.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state,
    and describe_availability_zones says nothing about instance types. Letting AWS choose the AZ
    is how a subnet lands in a zone that cannot run the instance type, and the follow-up
    RunInstances fails 'Unsupported' — an error that reads exactly like a fidelity failure.
    """
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert len(usable) >= n, (
        f"{ctx.region} offers {want!r} in available AZs {usable!r}; this check needs {n}"
    )
    return usable[:n]


def _vpc_estate(ctx, n_azs=2):
    """A self-contained public VPC: IGW, a default route, one subnet per usable AZ, and an SG.
    It does not depend on a default VPC, and every subnet routes to the internet gateway as an
    internet-facing Classic ELB requires."""
    ec2 = ctx.client("ec2")
    azs = _usable_azs(ctx, n=n_azs)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.180.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": list(_TAGS)}],
    )["InternetGateway"]["InternetGatewayId"]

    def _drop_igw():
        _teardown(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id),
                  "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached")
        _teardown(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id),
                  "InvalidInternetGatewayID.NotFound")

    ctx.on_cleanup(_drop_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    # The VPC's main route table is deleted with the VPC, so only the route itself is added.
    rtb_id = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]},
    ])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(azs):
        sub_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.180.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": list(_TAGS)}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sub_id)

        def _drop_subnet(sid=sub_id):
            _teardown(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), "InvalidSubnetID.NotFound")

        ctx.on_cleanup(_drop_subnet)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="sim2real classic-elb data-plane ingress",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": list(_TAGS)}],
    )["GroupId"]

    def _drop_sg():
        _teardown(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound")

    ctx.on_cleanup(_drop_sg)
    return vpc_id, subnet_ids, sg_id


def _create_clb(ctx, subnet_ids, sg_id, listeners=None, **kwargs):
    """An internet-facing Classic ELB whose teardown, registered at creation, deletes it
    and waits until it is gone."""
    elb = ctx.client("elb")
    name = _clamp_name(kwargs.pop("LoadBalancerName", None)
                       or ctx.unique_name("sim2real-behav-clb-"))
    params = dict(
        LoadBalancerName=name,
        Listeners=listeners or [{
            "Protocol": "HTTP", "LoadBalancerPort": 80,
            "InstanceProtocol": "HTTP", "InstancePort": 80,
        }],
        Subnets=list(subnet_ids), SecurityGroups=[sg_id],
        Scheme="internet-facing", Tags=list(_TAGS),
    )
    params.update(kwargs)
    created = _retry_throttled(lambda: elb.create_load_balancer(**params))

    def _drop_lb():
        _teardown(lambda: elb.delete_load_balancer(LoadBalancerName=name), "LoadBalancerNotFound")
        # DeleteLoadBalancer returns before the ENIs are released: poll the name out of Describe
        # before the network deletes behind this one run.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.describe_load_balancers(LoadBalancerNames=[name])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(f"load balancer {name} still described 60 s after DeleteLoadBalancer")
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return {"name": name, "dns": created["DNSName"]}


def _instance_state(ctx, lb_name, iid):
    """One instance's entry in DescribeInstanceHealth, or None if absent."""
    states = ctx.client("elb").describe_instance_health(
        LoadBalancerName=lb_name, Instances=[{"InstanceId": iid}])["InstanceStates"]
    for st in states:
        if st["InstanceId"] == iid:
            return st
    return None


def _fast_health_check(target):
    """The tightest health check Classic ELB accepts, so a transition is seconds not minutes.

    Timeout must be strictly less than Interval, and both thresholds have a floor of 2.
    """
    return {"Target": target, "Interval": 5, "Timeout": 2,
            "UnhealthyThreshold": 2, "HealthyThreshold": 2}


# ===== end helpers =====


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """Registering a well-formed but nonexistent instance id is rejected InvalidInstance and leaves
    the registration set empty, while the same load balancer still accepts a health-check
    reconfiguration."""
    elb = ctx.client("elb")
    vpc_id, subnet_ids, sg_id = _vpc_estate(ctx, n_azs=2)
    lb = _create_clb(ctx, [subnet_ids[0]], sg_id)
    absent = "i-0123456789abcdef0"

    # message varies: it embeds the request id of ELB's internal EC2 call, which no response
    # exposes ('... Invalid id: "<id>" (Service: AmazonEC2; ...; Request ID: <uuid>; Proxy: null)').
    code, _message = _error(lambda: elb.register_instances_with_load_balancer(
        LoadBalancerName=lb["name"], Instances=[{"InstanceId": absent}]))
    assert code == "InvalidInstance", (
        f"registering nonexistent instance {absent!r} raised {code!r}, expected 'InvalidInstance'"
    )

    # EFFECT ABSENT: nothing was registered. Scoped to THIS load balancer, so a sibling run in
    # the same account cannot make the emptiness a property of anything but this balancer.
    registered = elb.describe_instance_health(
        LoadBalancerName=lb["name"])["InstanceStates"]
    assert registered == [], (
        f"after a rejected registration the load balancer reported instances {registered!r}, "
        f"expected none — the rejected call must not have registered anything"
    )

    # And the specific id is absent, not merely absent from an empty overall list.
    code_health, message_health = _error(lambda: elb.describe_instance_health(
        LoadBalancerName=lb["name"], Instances=[{"InstanceId": absent}]))
    assert code_health == "InvalidInstance", (
        f"DescribeInstanceHealth for the unregistered id {absent!r} raised {code_health!r}, "
        f"expected 'InvalidInstance'"
    )
    expected_health = f"Could not find EC2 instance {absent}."
    assert message_health == expected_health, (
        f"DescribeInstanceHealth for the unregistered id {absent!r} raised message "
        f"{message_health!r}, expected {expected_health!r}"
    )

    # POSITIVE CONTROL: the load balancer is healthy and still mutable after the rejection.
    wanted = _fast_health_check("HTTP:80/ping")
    got = elb.configure_health_check(
        LoadBalancerName=lb["name"], HealthCheck=wanted)["HealthCheck"]
    assert got == wanted, (
        f"ConfigureHealthCheck after the rejected registration returned {got!r}, expected "
        f"{wanted!r} — the rejection must not have left the load balancer unusable"
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
