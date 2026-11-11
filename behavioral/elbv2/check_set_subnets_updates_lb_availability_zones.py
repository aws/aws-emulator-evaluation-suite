"""set-subnets-updates-lb-availability-zones."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-subnets-updates-lb-availability-zones"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetSubnets changes the AZ set an ALB spans, visible immediately in DescribeLoadBalancers."""
    elbv2 = ctx.client("elbv2")
    # Shared across every delete-with-retry cleanup callback below: DeleteLoadBalancer returns
    # before its ENIs actually detach, so an immediate DeleteSubnet/DeleteVpc can race a lingering
    # ENI and fail with DependencyViolation. All retries share one deadline so the combined
    # teardown still fits inside ctx.on_cleanup's own budget (see _delete_with_retry).
    cleanup_deadline = [None]
    az_to_subnet = _ensure_azs_subnets(ctx, cleanup_deadline, min_azs=3)
    azs = sorted(az_to_subnet.keys())
    az_a, az_b, az_c = azs[0], azs[1], azs[2]

    name = _short_alnum_name(ctx, "sim2real-svlb")
    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=[az_to_subnet[az_a], az_to_subnet[az_b]],
        Type="application",
        Scheme="internal",
        Tags=_tags_kv(),
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))

    _wait_lb_not_provisioning(ctx, lb_arn)

    before = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    before_azs = {z["ZoneName"] for z in before["AvailabilityZones"]}
    expected_before = {az_a, az_b}
    assert before_azs == expected_before, f"expected initial AZs {expected_before}, got {before_azs}"

    # Swap az_a out for az_c: the LB should now span {az_b, az_c}, not the original set.
    elbv2.set_subnets(
        LoadBalancerArn=lb_arn,
        Subnets=[az_to_subnet[az_b], az_to_subnet[az_c]],
    )

    after = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
    after_azs = {z["ZoneName"] for z in after["AvailabilityZones"]}
    expected_after = {az_b, az_c}
    assert after_azs == expected_after, f"expected updated AZs {expected_after}, got {after_azs}"
    assert az_a not in after_azs, f"az_a ({az_a}) should have been dropped by SetSubnets but is still present in {after_azs}"


# ===== helpers =====

def _tags_kv() -> list:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]


def _short_alnum_name(ctx, prefix: str, max_len: int = 32) -> str:
    raw = ctx.unique_name(f"{prefix}-").replace("_", "-").lower()
    if len(raw) > max_len:
        raw = raw[-max_len:]
    raw = raw.strip("-")
    return raw


def _delete_with_retry(fn, deadline_holder, per_wait: float = 3.0) -> None:
    """Retry ``fn`` while it fails with DependencyViolation, until the shared deadline passes.

    ALB deletion returns before its ENIs actually detach from their subnets, so an immediate
    DeleteSubnet/DeleteVpc issued right after DeleteLoadBalancer can race a lingering ENI. The
    deadline is shared across every call in this check's teardown (initialised on first use) so
    the combined retries still fit inside ``ctx.on_cleanup``'s own ~60s budget rather than each
    call greedily using its own.
    """
    if deadline_holder[0] is None:
        deadline_holder[0] = time.monotonic() + 50.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "DependencyViolation" or time.monotonic() >= deadline_holder[0]:
                raise
            time.sleep(per_wait)


def _ensure_azs_subnets(ctx, cleanup_deadline: list, min_azs: int = 2) -> dict:
    """Create-or-adopt a subnet-per-AZ map spanning at least ``min_azs`` AZs.

    A freshly provisioned account may have no default VPC at all, so this never assumes
    one exists: it adopts the default VPC's subnets when there are enough of them, and otherwise
    provisions a small dedicated VPC with one subnet per AZ (no internet gateway or route table
    needed -- the load balancer this check creates is internal-scheme only).
    """
    ec2 = ctx.client("ec2")
    adopted = _adopt_default_vpc_azs(ec2, min_azs, ctx=ctx)
    if adopted is not None:
        return adopted
    return _create_dedicated_vpc_azs(ctx, ec2, cleanup_deadline, min_azs)


def _adopt_default_vpc_azs(ec2, min_azs: int, *, ctx):
    # The DescribeVpcs filter is "isDefault" (camelCase) -- there is no "is-default" filter.
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az: dict = {}
    for s in sorted(subnets, key=lambda s: s["SubnetId"]):
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < min_azs:
        return None
    azs = sorted(by_az)[:min_azs]
    return {az: by_az[az] for az in azs}


def _create_dedicated_vpc_azs(ctx, ec2, cleanup_deadline: list, min_azs: int) -> dict:
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    if len(azs) < min_azs:
        raise AssertionError(f"region exposes only {len(azs)} available AZs, need at least {min_azs}")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.66.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": _tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), cleanup_deadline))

    by_az: dict = {}
    for i, az in enumerate(azs[:min_azs]):
        zone = az["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.66.{i}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": _tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_with_retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), cleanup_deadline)
        )
        by_az[zone] = subnet_id
    return by_az


def _wait_lb_not_provisioning(ctx, lb_arn: str, timeout_s: float = 180.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        last_code = lb["State"]["Code"]
        if last_code != "provisioning":
            return
        time.sleep(3)
    raise AssertionError(
        f"load balancer never left 'provisioning' state within {timeout_s}s (last seen: {last_code!r})"
    )


# Subnet / security group / VPC deletes fail with DependencyViolation while AWS-managed ENIs of an
# asynchronously deleted resource (e.g. a load balancer) remain, so wait (bounded) for them to go,
# retry inside one shared window, and finally raise naming the ENIs still attached.
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
