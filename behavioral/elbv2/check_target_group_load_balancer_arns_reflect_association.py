"""target-group-load-balancer-arns-reflect-association."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-group-load-balancer-arns-reflect-association"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A target group's LoadBalancerArns field is empty until it is referenced by a listener,
    and reflects the associated load balancer's ARN afterward."""
    net = _setup_network(ctx)
    elbv2 = ctx.client("elbv2")
    tg = _create_target_group(ctx, net["vpc_id"])
    tg_arn = tg["TargetGroupArn"]

    described_before = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert described_before["LoadBalancerArns"] == [], described_before["LoadBalancerArns"]

    lb = _create_alb(ctx, net["subnet_ids"])
    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]
    assert listener["ListenerArn"], "create_listener did not return a ListenerArn"

    described_after = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert described_after["LoadBalancerArns"] == [lb["LoadBalancerArn"]], described_after["LoadBalancerArns"]

    # Terminal read: an independent read (DescribeTargetGroups filtered by LoadBalancerArn,
    # not the mutating create_listener call) at the destination confirms the association.
    filtered = elbv2.describe_target_groups(LoadBalancerArn=lb["LoadBalancerArn"])["TargetGroups"]
    filtered_arns = {t["TargetGroupArn"] for t in filtered}
    assert tg_arn in filtered_arns, filtered_arns


# ===== helpers =====
_GONE_CODES = ("LoadBalancerNotFound", "TargetGroupNotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound")


def _safe(fn):
    """Teardown delete: an already-gone resource is clean; every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE_CODES:
            raise


def _retry_delete(fn, attempts: int = 10, delay: float = 3.0) -> None:
    """DeleteLoadBalancer cascades its listener asynchronously, so an immediately
    following DeleteTargetGroup can race it with ResourceInUse. Bounded retry, not a
    sleep: it waits only for that specific transient conflict and gives up loudly on
    anything else."""
    import time

    last: Exception | None = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - botocore ClientError shape varies
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code != "ResourceInUse":
                raise
            last = exc
            time.sleep(delay)
    if last is not None:
        raise last


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}]


def _setup_network(ctx, num_subnets=2):
    """Create-or-adopt: use the shared network's subnets if it has enough across AZs,
    otherwise provision a scratch VPC. A freshly provisioned account may have no
    shared network at all, so this check must not depend on one existing."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = [by_az[az] for az in sorted(by_az)][:num_subnets]
        if len(subnet_ids) >= num_subnets:
            return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}

    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv())
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.create_tags(Resources=[sid], Tags=_tags_kv())
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application", Tags=_tags_kv())
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip", "Tags": _tags_kv()}
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: _retry_delete(lambda: elbv2.delete_target_group(TargetGroupArn=arn), attempts=60, delay=10.0)))
    return tg


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
