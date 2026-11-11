"""delete-load-balancer-is-idempotent-and-removes-it-from-describe."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-load-balancer-is-idempotent-and-removes-it-from-describe"
GROUP = 'lifecycle'
SERVICES = ['elb']

# ===== helpers =====
_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


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


def _teardown(fn, *gone_codes):
    """Run one teardown call; only the resource's not-found codes count as already deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in gone_codes:
            raise


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _internal_network(ctx, n=2):
    """Own VPC and one subnet per availability zone, tagged at creation and independent
    of a default VPC. No internet gateway: nothing here sends a data-plane request, so the load
    balancer is internal."""
    ec2 = ctx.client("ec2")
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= n, f"{ctx.region} has {len(azs)} available zones {azs!r}, need {n}"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.89.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": list(_TAGS)}],
    )["Vpc"]["VpcId"]

    def _drop_vpc():
        _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_drop_vpc)
    subnet_ids = []
    for i, az in enumerate(azs[:n]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.89.{i}.0/24", AvailabilityZone=az,
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
    """Billable resource: the waited teardown is registered AT CREATION (cleanups run LIFO). This
    check deletes the load balancer itself; the registered teardown is what covers the paths where
    an assertion fails before it gets there, and it tolerates the already-deleted case because
    DeleteLoadBalancer is idempotent — which is the very thing under test."""
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


@tags("axis:happy-path", "concern:representation", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """DeleteLoadBalancer is idempotent (a repeat delete and a delete of a never-existing name both
    return 200), while every read of the deleted load balancer becomes LoadBalancerNotFound and it
    leaves the paginated listing."""
    elb = ctx.client("elb")
    vpc_id, subnet_ids, _azs = _internal_network(ctx)
    sg_id = _sg(ctx, vpc_id)
    lb_name, dns_name = _create_classic_lb(ctx, subnet_ids, sg_id)

    # Present before the delete, both by name and in the paginated account-wide listing.
    described = elb.describe_load_balancers(
        LoadBalancerNames=[lb_name])["LoadBalancerDescriptions"][0]
    assert described["DNSName"] == dns_name, (
        f"DescribeLoadBalancers reports DNSName {described['DNSName']!r} for {lb_name}, expected "
        f"the {dns_name!r} CreateLoadBalancer minted"
    )
    assert lb_name in _names_with_prefix(ctx, lb_name), (
        f"the load balancer {lb_name!r} this check just created is absent from the paginated "
        f"listing filtered to its own name"
    )

    first = elb.delete_load_balancer(LoadBalancerName=lb_name)
    assert first["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the first DeleteLoadBalancer returned HTTP "
        f"{first['ResponseMetadata']['HTTPStatusCode']}, expected 200"
    )

    # The read flips to a 400 — polled, because the delete is asynchronous.
    not_found = f"There is no ACTIVE Load Balancer named '{lb_name}'"
    code, message = _poll_until(
        lambda: _error(lambda: elb.describe_load_balancers(LoadBalancerNames=[lb_name])),
        lambda e: e[0] == "LoadBalancerNotFound",
        timeout_s=120, interval_s=3,
        description=f"DescribeLoadBalancers reporting LoadBalancerNotFound for {lb_name}",
    )
    assert code == "LoadBalancerNotFound", (
        f"describing the deleted load balancer failed with {code!r}, expected LoadBalancerNotFound"
    )
    assert message == not_found, (
        f"describing the deleted load balancer failed with message {message!r}, expected "
        f"{not_found!r}"
    )
    health_code, health_message = _error(
        lambda: elb.describe_instance_health(LoadBalancerName=lb_name))
    assert health_code == "LoadBalancerNotFound", (
        f"DescribeInstanceHealth for the deleted load balancer failed with {health_code!r}, "
        f"expected LoadBalancerNotFound"
    )
    assert health_message == not_found, (
        f"DescribeInstanceHealth for the deleted load balancer failed with message "
        f"{health_message!r}, expected {not_found!r}"
    )
    assert _names_with_prefix(ctx, lb_name) == [], (
        f"the deleted load balancer still appears in the paginated listing: "
        f"{_names_with_prefix(ctx, lb_name)!r}"
    )

    # The SAME delete, repeated, is still a 200 — the mutation is idempotent where the read is not.
    second = elb.delete_load_balancer(LoadBalancerName=lb_name)
    assert second["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the second DeleteLoadBalancer returned HTTP "
        f"{second['ResponseMetadata']['HTTPStatusCode']}, expected 200 — this API does not 404 a "
        f"delete"
    )
    # And so is a delete of a name that never existed at all, in this same namespace.
    never = ctx.unique_name("sim2real-clb-")
    absent = elb.delete_load_balancer(LoadBalancerName=never)
    assert absent["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"DeleteLoadBalancer for the never-created name {never!r} returned HTTP "
        f"{absent['ResponseMetadata']['HTTPStatusCode']}, expected 200"
    )
    never_code, never_message = _error(
        lambda: elb.describe_load_balancers(LoadBalancerNames=[never]))
    assert never_code == "LoadBalancerNotFound", (
        f"describing the never-created name {never!r} failed with {never_code!r}, expected "
        f"LoadBalancerNotFound — the read is strict about exactly the name the delete forgave"
    )
    never_expected = f"There is no ACTIVE Load Balancer named '{never}'"
    assert never_message == never_expected, (
        f"describing the never-created name {never!r} failed with message {never_message!r}, "
        f"expected {never_expected!r}"
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
