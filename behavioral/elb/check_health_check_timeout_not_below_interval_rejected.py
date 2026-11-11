"""health-check-timeout-not-below-interval-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "health-check-timeout-not-below-interval-rejected"
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
    """Own VPC and one subnet per availability zone, tagged at creation and independent
    of a default VPC. No internet gateway: nothing here sends a data-plane request, so the load
    balancer is internal."""
    ec2 = ctx.client("ec2")
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= n, f"{ctx.region} has {len(azs)} available zones {azs!r}, need {n}"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.86.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)
    subnet_ids = []
    for i, az in enumerate(azs[:n]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.86.{i}.0/24", AvailabilityZone=az,
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
    created = elb.create_load_balancer(
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
    return lb_name, created["DNSName"]


def _health_check(ctx, lb_name):
    return ctx.client("elb").describe_load_balancers(
        LoadBalancerNames=[lb_name])["LoadBalancerDescriptions"][0]["HealthCheck"]


# ===== end helpers =====


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c1",
    "cap:c5",
    "plane:control",
)
def run(ctx) -> None:
    """ConfigureHealthCheck rejects a Timeout not below the Interval with ValidationError, leaves the
    previously stored health check untouched, and accepts the same request once only the timeout
    is lowered."""
    elb = ctx.client("elb")
    vpc_id, subnet_ids, _azs = _internal_network(ctx)
    sg_id = _sg(ctx, vpc_id)
    lb_name, _dns = _create_classic_lb(ctx, subnet_ids, sg_id)

    default_hc = _health_check(ctx, lb_name)
    assert default_hc["Target"] == "TCP:80", (
        f"a load balancer created with an HTTP 80 listener reported default health-check target "
        f"{default_hc['Target']!r}, expected 'TCP:80'"
    )

    # POSITIVE CONTROL first, so the stored state the rejection must not disturb is one this
    # check put there deliberately.
    accepted = elb.configure_health_check(
        LoadBalancerName=lb_name,
        HealthCheck={"Target": "HTTP:80/ok", "Interval": 10, "Timeout": 4,
                     "UnhealthyThreshold": 2, "HealthyThreshold": 2})["HealthCheck"]
    assert accepted == {"Target": "HTTP:80/ok", "Interval": 10, "Timeout": 4,
                        "UnhealthyThreshold": 2, "HealthyThreshold": 2}, (
        f"ConfigureHealthCheck echoed {accepted!r}, expected exactly the configuration sent"
    )

    # Break exactly one field: a timeout equal to the interval (the boundary), then one above it.
    equal_code, equal_message = _error(lambda: elb.configure_health_check(
        LoadBalancerName=lb_name,
        HealthCheck={"Target": "HTTP:80/ok", "Interval": 10, "Timeout": 10,
                     "UnhealthyThreshold": 2, "HealthyThreshold": 2}))
    assert equal_code == "ValidationError", (
        f"a health check with Timeout == Interval failed with {equal_code!r}, expected "
        f"ValidationError"
    )
    assert equal_message == "HealthCheck timeout must be less than interval. ", (
        f"a health check with Timeout == Interval failed with message {equal_message!r}, expected "
        f"'HealthCheck timeout must be less than interval. ' (with its trailing space)"
    )
    above_code, above_message = _error(lambda: elb.configure_health_check(
        LoadBalancerName=lb_name,
        HealthCheck={"Target": "HTTP:80/ok", "Interval": 10, "Timeout": 11,
                     "UnhealthyThreshold": 2, "HealthyThreshold": 2}))
    assert above_code == "ValidationError", (
        f"a health check with Timeout > Interval failed with {above_code!r}, expected "
        f"ValidationError"
    )
    assert above_message == "HealthCheck timeout must be less than interval. ", (
        f"a health check with Timeout > Interval failed with message {above_message!r}, expected "
        f"'HealthCheck timeout must be less than interval. ' (with its trailing space)"
    )

    # EFFECT ABSENT: neither rejected call moved any field of the stored health check.
    stored = _health_check(ctx, lb_name)
    assert stored == accepted, (
        f"after two rejected ConfigureHealthCheck calls the stored health check is {stored!r}, "
        f"expected the last accepted one {accepted!r} — a rejected call must not partially apply"
    )

    # And the boundary is where AWS says it is: Timeout one below Interval is accepted.
    boundary = elb.configure_health_check(
        LoadBalancerName=lb_name,
        HealthCheck={"Target": "HTTP:80/ok", "Interval": 10, "Timeout": 9,
                     "UnhealthyThreshold": 2, "HealthyThreshold": 2})["HealthCheck"]
    assert boundary["Timeout"] == 9 and boundary["Interval"] == 10, (
        f"a health check with Timeout one second below Interval was stored as {boundary!r}, "
        f"expected Timeout 9 / Interval 10 — so the rejections above are the strict inequality "
        f"and not a wider refusal"
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
