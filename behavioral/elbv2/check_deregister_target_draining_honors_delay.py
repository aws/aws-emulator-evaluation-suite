"""deregister-target-draining-honors-delay."""
from __future__ import annotations

import ipaddress
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-target-draining-honors-delay"
GROUP = 'target-registration'
SERVICES = ['elbv2']
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0

# ===== helpers =====
_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_DRAIN_S = 60


def _clamp_name(name, maxlen=32):
    return name[:maxlen].rstrip("-")


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


def _poll_until(probe, predicate, *, timeout_s=POLL_BUDGET_S, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_NET_TAGS = _TAGS


def _own_network(ctx, n_subnets=1):
    """Create a VPC with public subnets in distinct AZs and an internet gateway route.

    Returns (vpc_id, subnets, default sg_id); cleanup waits for leftover ENIs, then deletes in order."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    subnets: list = []
    igw_id = None

    def _teardown_network():
        deadline = time.monotonic() + POLL_BUDGET_S
        for subnet_id in subnets:
            while True:
                if not ec2.describe_network_interfaces(
                    Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
                ).get("NetworkInterfaces"):
                    break
                if time.monotonic() > deadline:
                    raise AssertionError(f"ENIs still attached in {subnet_id}; network not torn down")
                time.sleep(10)
            _retry_dependency(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s), deadline,
                              gone=("InvalidSubnetID.NotFound",))
        if igw_id:
            _retry_dependency(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
                              deadline, gone=("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"))
            _retry_dependency(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id), deadline,
                              gone=("InvalidInternetGatewayID.NotFound",))
        _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id), deadline, gone=("InvalidVpcID.NotFound",))

    ctx.on_cleanup(_teardown_network)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    assert len(zones) >= n_subnets, f"expected {n_subnets} available AZs, got {zones!r}"
    for i, az in enumerate(zones[:n_subnets]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.198.0.{i * 64}/26",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
        )["Subnet"]["SubnetId"]
        subnets.append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _NET_TAGS}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
        "RouteTables"
    ][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = next(
        sg["GroupId"]
        for sg in ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        if sg["GroupName"] == "default"
    )
    return vpc_id, subnets, sg_id


def _retry_dependency(call, deadline, *, gone=()):
    """Run a teardown call, retrying while a dependency (a detaching ENI) still blocks it."""
    while True:
        try:
            call()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in gone:
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _unused_ip_in(subnet, back=3):
    net = ipaddress.ip_network(subnet["CidrBlock"])
    return str(net.broadcast_address - back)


def _create_load_balancer(ctx, subnet_ids, **kwargs):
    """Billable resource: waited teardown registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-lb-"))
    params = dict(
        Name=name, Subnets=subnet_ids, Type="application",
        Scheme="internal", Tags=list(_TAGS),
    )
    params.update(kwargs)
    lb = _retry_throttled(lambda: elb.create_load_balancer(**params))["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _drop_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise
            return
        for _ in range(90):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[arn])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                    raise
                return
            time.sleep(2)

    ctx.on_cleanup(_drop_lb)
    return lb


def _wait_for_lb_active(ctx, lb_arn, timeout_s=POLL_BUDGET_S):
    elb = ctx.client("elbv2")
    lb = _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda x: x["State"]["Code"] in ("active", "active_impaired", "failed"),
        timeout_s=timeout_s, interval_s=10,
        description="load balancer reaching a terminal provisioning state",
    )
    assert lb["State"]["Code"] == "active", f"load balancer state {lb['State']!r}, expected active"
    return lb


def _create_target_group(ctx, **kwargs):
    elb = ctx.client("elbv2")
    name = _clamp_name(kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-tg-"))
    params = dict(Name=name, Tags=list(_TAGS))
    params.update(kwargs)
    tg = _retry_throttled(lambda: elb.create_target_group(**params))["TargetGroups"][0]
    arn = tg["TargetGroupArn"]

    def _drop_tg():
        # A target group stays ResourceInUse until its listener is released.
        deadline = time.monotonic() + 60
        while True:
            try:
                elb.delete_target_group(TargetGroupArn=arn)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "TargetGroupNotFound":
                    return
                if code != "ResourceInUse" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_drop_tg)
    return tg


def _create_listener(ctx, lb_arn, **kwargs):
    elb = ctx.client("elbv2")
    params = dict(LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80)
    params.update(kwargs)
    listener = _retry_throttled(lambda: elb.create_listener(**params))["Listeners"][0]
    arn = listener["ListenerArn"]
    def _drop_listener():
        try:
            elb.delete_listener(ListenerArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ListenerNotFound":
                raise

    ctx.on_cleanup(_drop_listener)
    return listener


def _health_of(ctx, tg_arn, ip, port):
    """TargetHealth dict for `ip:port` in the group's FULL health list, or None if absent."""
    descs = ctx.client("elbv2").describe_target_health(
        TargetGroupArn=tg_arn,
    )["TargetHealthDescriptions"]
    for desc in descs:
        tgt = desc.get("Target") or {}
        if tgt.get("Id") == ip and int(tgt.get("Port", port)) == port:
            return desc.get("TargetHealth") or {}
    return None


def _set_attr(ctx, tg_arn, key, value):
    elb = ctx.client("elbv2")
    _retry_throttled(lambda: elb.modify_target_group_attributes(
        TargetGroupArn=tg_arn, Attributes=[{"Key": key, "Value": value}],
    ))
    attrs = {
        a["Key"]: a["Value"]
        for a in elb.describe_target_group_attributes(TargetGroupArn=tg_arn)["Attributes"]
    }
    assert attrs.get(key) == value, f"{key} did not round-trip: {attrs.get(key)!r} != {value!r}"
    return attrs
# ===== end helpers =====


# timing:real-time — retention: 60 s https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """An in-use target stays registered for deregistration_delay.timeout_seconds after deregister,
    so in-flight requests finish; a group with no load balancer never drains. The deleted load
    balancer and target group then read not-found with exact messages."""
    elb = ctx.client("elbv2")
    vpc_id, subnet_ids, _sg = _own_network(ctx, n_subnets=2)
    subnets = ctx.client("ec2").describe_subnets(SubnetIds=subnet_ids)["Subnets"]
    subnets.sort(key=lambda sub: subnet_ids.index(sub["SubnetId"]))

    lb = _create_load_balancer(ctx, subnet_ids)
    _wait_for_lb_active(ctx, lb["LoadBalancerArn"])

    tg = _create_target_group(
        ctx, TargetType="ip", Protocol="HTTP", Port=80, VpcId=vpc_id,
        HealthCheckIntervalSeconds=10, HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2, UnhealthyThresholdCount=2,
    )
    tg_arn = tg["TargetGroupArn"]

    # Default first, then the explicit delay this check measures against.
    defaults = {
        a["Key"]: a["Value"]
        for a in elb.describe_target_group_attributes(TargetGroupArn=tg_arn)["Attributes"]
    }
    assert defaults.get("deregistration_delay.timeout_seconds") == "300", defaults
    _set_attr(ctx, tg_arn, "deregistration_delay.timeout_seconds", str(_DRAIN_S))

    # Draining exists only for a target group a listener actually routes to.
    _create_listener(
        ctx, lb["LoadBalancerArn"], Port=80, Protocol="HTTP",
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )

    ip = _unused_ip_in(subnets[0], back=3)
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80}]))

    # The target must actually be in use by the load balancer before draining means
    # anything: wait for it to leave `unused`.
    in_use = _poll_until(
        lambda: _health_of(ctx, tg_arn, ip, 80),
        lambda h: h is not None and h.get("State") not in (None, "unused"),
        interval_s=3,
        description="registered target becoming in-use by the attached load balancer",
    )
    assert in_use.get("State") in ("initial", "unhealthy", "healthy"), in_use

    elb.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80}])
    dereg_at = time.monotonic()

    _poll_until(
        lambda: _health_of(ctx, tg_arn, ip, 80),
        lambda h: h is None,
        interval_s=2,
        description="deregistered target finally leaving the registered set",
    )
    drained_after = time.monotonic() - dereg_at
    assert drained_after >= _DRAIN_S - 10, (
        f"target left the group after {drained_after:.1f}s but "
        f"deregistration_delay.timeout_seconds={_DRAIN_S} requires it to drain at least that long"
    )

    # Control: the same delay on a group with NO load balancer must not create a
    # draining state — nothing is in flight, so deregistration is immediate.
    ctrl = _create_target_group(
        ctx, TargetType="ip", Protocol="HTTP", Port=80, VpcId=vpc_id,
    )
    ctrl_arn = ctrl["TargetGroupArn"]
    _set_attr(ctx, ctrl_arn, "deregistration_delay.timeout_seconds", str(_DRAIN_S))
    ctrl_ip = _unused_ip_in(subnets[0], back=4)
    _retry_throttled(lambda: elb.register_targets(
        TargetGroupArn=ctrl_arn, Targets=[{"Id": ctrl_ip, "Port": 80}]))
    _poll_until(
        lambda: _health_of(ctx, ctrl_arn, ctrl_ip, 80),
        lambda h: h is not None,
        interval_s=3,
        description="control target appearing in the unattached group's health list",
    )
    elb.deregister_targets(TargetGroupArn=ctrl_arn, Targets=[{"Id": ctrl_ip, "Port": 80}])
    ctrl_states = []

    def _ctrl_probe():
        health = _health_of(ctx, ctrl_arn, ctrl_ip, 80)
        ctrl_states.append(None if health is None else health.get("State"))
        return health

    _poll_until(
        _ctrl_probe, lambda h: h is None,
        interval_s=3,
        description="control target leaving the unattached group without draining",
    )
    assert "draining" not in ctrl_states, (
        f"target in a target group with no load balancer entered draining: {ctrl_states}"
    )

    # The load balancer is deleted and gone: unreadable by ARN and name, and unusable.
    lb_arn, lb_name = lb["LoadBalancerArn"], lb["LoadBalancerName"]
    _retry_throttled(lambda: elb.delete_load_balancer(LoadBalancerArn=lb_arn))
    _poll_until(
        lambda: _lb_present(elb, lb_arn),
        lambda present: present is False,
        interval_s=3,
        description=f"load balancer {lb_name} reading not-found after DeleteLoadBalancer",
    )
    refused = _expect_error(lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn]), ("LoadBalancerNotFound",))
    expected_message = "One or more load balancers not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    refused = _expect_error(lambda: elb.describe_load_balancers(Names=[lb_name]), ("LoadBalancerNotFound",))
    expected_message = f"Load balancers '[{lb_name}]' not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    refused = _expect_error(lambda: elb.add_tags(ResourceArns=[lb_arn], Tags=[{"Key": "after", "Value": "delete"}]),
                            ("LoadBalancerNotFound",))
    expected_message = "One or more load balancers not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # The drained target group is deleted and gone: unreadable by ARN and name, refuses targets.
    tg_name = tg["TargetGroupName"]
    # The listener went with the load balancer; the group's in-use link releases as bounded
    # convergence, so a ResourceInUse here is retried until the poll budget, not graded.
    _poll_until(
        lambda: _delete_tg_settled(elb, tg_arn),
        lambda done: done,
        interval_s=3,
        description=f"DeleteTargetGroup {tg_name} accepted once its load balancer is gone",
    )
    refused = _expect_error(lambda: elb.describe_target_groups(TargetGroupArns=[tg_arn]), ("TargetGroupNotFound",))
    expected_message = "One or more target groups not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    refused = _expect_error(lambda: elb.describe_target_groups(Names=[tg_name]), ("TargetGroupNotFound",))
    expected_message = "One or more target groups not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    refused = _expect_error(lambda: elb.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": ip, "Port": 80}]),
                            ("TargetGroupNotFound",))
    expected_message = f"Target groups '{tg_arn}' not found"
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'


def _delete_tg_settled(elb, arn):
    try:
        _retry_throttled(lambda: elb.delete_target_group(TargetGroupArn=arn))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceInUse":
            return False
        raise
    return True


def _lb_present(elb, arn):
    try:
        elb.describe_load_balancers(LoadBalancerArns=[arn])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "LoadBalancerNotFound":
            return False
        raise
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
