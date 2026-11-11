"""duplicate-load-balancer-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-load-balancer-name-rejected"
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
    balancers are internal."""
    ec2 = ctx.client("ec2")
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= n, f"{ctx.region} has {len(azs)} available zones {azs!r}, need {n}"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.85.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)
    subnet_ids = []
    for i, az in enumerate(azs[:n]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.85.{i}.0/24", AvailabilityZone=az,
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


def _create_classic_lb(ctx, subnet_ids, sg_id, *, name=None, listeners=None):
    """Billable resource: the waited teardown is registered AT CREATION (cleanups run LIFO)."""
    elb = ctx.client("elb")
    lb_name = name or ctx.unique_name("sim2real-clb-")  # 25 chars; the API ceiling is 32
    created = elb.create_load_balancer(
        LoadBalancerName=lb_name,
        Listeners=listeners or [{"Protocol": "HTTP", "LoadBalancerPort": 80,
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


def _describe_one(ctx, lb_name):
    return ctx.client("elb").describe_load_balancers(
        LoadBalancerNames=[lb_name])["LoadBalancerDescriptions"][0]


def _names_with_prefix(ctx, prefix):
    """Every load balancer whose name starts with `prefix`, over the whole
    paginated listing, so other load balancers in the account do not affect the count."""
    elb = ctx.client("elb")
    found = []
    for page in elb.get_paginator("describe_load_balancers").paginate():
        found += [d["LoadBalancerName"] for d in page["LoadBalancerDescriptions"]
                  if d["LoadBalancerName"].startswith(prefix)]
    return found


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
    """A second CreateLoadBalancer under an existing name is rejected DuplicateLoadBalancerName, the
    rejected configuration does not reach the existing load balancer (still one, with its original
    listener), and the same request under a fresh name succeeds."""
    elb = ctx.client("elb")
    vpc_id, subnet_ids, _azs = _internal_network(ctx)
    sg_id = _sg(ctx, vpc_id)

    lb_name, _dns = _create_classic_lb(ctx, subnet_ids, sg_id)
    original = _describe_one(ctx, lb_name)
    original_listeners = [d["Listener"] for d in original["ListenerDescriptions"]]
    assert original_listeners == [{"Protocol": "HTTP", "LoadBalancerPort": 80,
                                  "InstanceProtocol": "HTTP", "InstancePort": 80}], (
        f"the load balancer was created with listeners {original_listeners!r}, expected exactly "
        f"the single HTTP 80 -> 80 listener this check asked for"
    )

    # Break exactly one thing: reuse the name, with a configuration that differs.
    code, message = _error(lambda: elb.create_load_balancer(
        LoadBalancerName=lb_name,
        Listeners=[{"Protocol": "TCP", "LoadBalancerPort": 81,
                    "InstanceProtocol": "TCP", "InstancePort": 8080}],
        Subnets=list(subnet_ids), SecurityGroups=[sg_id], Scheme="internal"))
    assert code == "DuplicateLoadBalancerName", (
        f"creating a second load balancer named {lb_name!r} failed with {code!r}, expected "
        f"DuplicateLoadBalancerName"
    )
    expected = (
        f"Load Balancer named {lb_name} already exists and it is configured with different "
        f"parameters."
    )
    assert message == expected, (
        f"creating a second load balancer named {lb_name!r} failed with message {message!r}, "
        f"expected {expected!r}"
    )

    # EFFECT ABSENT: the rejected configuration reached nothing.
    after = _describe_one(ctx, lb_name)
    after_listeners = [d["Listener"] for d in after["ListenerDescriptions"]]
    assert after_listeners == original_listeners, (
        f"after the rejected duplicate the load balancer carries listeners {after_listeners!r}, "
        f"expected its original {original_listeners!r} — the rejected call must not have applied"
    )
    assert after["DNSName"] == original["DNSName"], (
        f"the surviving load balancer's DNSName changed from {original['DNSName']!r} to "
        f"{after['DNSName']!r} across a rejected create"
    )
    matching = [n for n in _names_with_prefix(ctx, "sim2real-clb-") if n == lb_name]
    assert matching == [lb_name], (
        f"the paginated listing shows {matching!r} load balancers named {lb_name!r}, expected "
        f"exactly one"
    )

    # POSITIVE CONTROL: the identical request under a name that is free still succeeds, so the
    # rejection is attributable to the name collision and to nothing else about the request.
    second_name, second_dns = _create_classic_lb(
        ctx, subnet_ids, sg_id,
        listeners=[{"Protocol": "TCP", "LoadBalancerPort": 81,
                    "InstanceProtocol": "TCP", "InstancePort": 8080}])
    assert second_dns and second_dns != original["DNSName"], (
        f"the second load balancer was minted DNSName {second_dns!r}, expected a hostname "
        f"distinct from the first's {original['DNSName']!r}"
    )
    second_listeners = [d["Listener"] for d in _describe_one(ctx, second_name)[
        "ListenerDescriptions"]]
    assert second_listeners == [{"Protocol": "TCP", "LoadBalancerPort": 81,
                                "InstanceProtocol": "TCP", "InstancePort": 8080}], (
        f"the load balancer created under a free name carries listeners {second_listeners!r}, "
        f"expected the TCP 81 -> 8080 listener the duplicate had asked for"
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
