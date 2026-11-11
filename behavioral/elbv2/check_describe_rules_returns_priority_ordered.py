"""describe-rules-returns-priority-ordered."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "describe-rules-returns-priority-ordered"
GROUP = "ordering"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeRules returns rules in ascending-priority order (the order the
    listener evaluates them) regardless of the order in which they were created,
    with the default rule always sorted last."""
    elbv2 = ctx.client("elbv2")
    lb_arn = _create_alb(ctx)
    listener_arn = _create_listener(ctx, lb_arn)

    # Create rules in a deliberately non-ascending creation order.
    created_priorities = []
    for priority, path in [(50, "/p50*"), (10, "/p10*"), (30, "/p30*")]:
        _create_rule(ctx, listener_arn, priority, path)
        created_priorities.append(priority)

    rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    non_default = [r for r in rules if not r.get("IsDefault")]
    observed_priorities = [int(r["Priority"]) for r in non_default]

    assert observed_priorities == sorted(observed_priorities), (
        f"DescribeRules did not return ascending-priority order: {observed_priorities}"
    )
    assert observed_priorities == sorted(created_priorities), (
        f"expected {sorted(created_priorities)}, got {observed_priorities}"
    )

    default_rules = [r for r in rules if r.get("IsDefault")]
    assert len(default_rules) == 1, "expected exactly one default rule on the listener"
    assert rules[-1].get("IsDefault") is True, (
        "the default rule (evaluated last) must sort after all numbered priorities"
    )


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _create_network(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(
        Resources=[vpc_id],
        Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
    )
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        ec2.create_tags(Resources=[sid], Tags=_tags_kv())
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(sid)
    return vpc_id, subnet_ids


def _get_alb_network(ctx) -> tuple[str, list[str], str | None]:
    ec2 = ctx.client("ec2")
    vpc_id: str | None = None
    subnet_ids: list[str] = []
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    subnet_ids = [s["SubnetId"] for s in list(by_az.values())[:2]]
    if len(subnet_ids) < 2:
        # Fewer than two AZs available in the shared VPC: provision a dedicated network.
        vpc_id, subnet_ids = _create_network(ctx)
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return vpc_id, subnet_ids, sg_id


def _alb_name(ctx, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:32].rstrip("-")


def _create_alb(ctx) -> str:
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids, sg_id = _get_alb_network(ctx)
    kwargs: dict[str, Any] = dict(
        Name=_alb_name(ctx, "ord2"),
        Subnets=subnet_ids,
        Type="application",
        Scheme="internet-facing",
        Tags=_tags_kv(),
    )
    if sg_id:
        kwargs["SecurityGroups"] = [sg_id]
    lb = elbv2.create_load_balancer(**kwargs)["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    return lb_arn


def _create_listener(ctx, lb_arn: str, port: int = 80) -> str:
    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=port,
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "StatusCode": "200",
                    "ContentType": "text/plain",
                    "MessageBody": "default",
                },
            }
        ],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _create_rule(ctx, listener_arn: str, priority: int, path: str) -> str:
    elbv2 = ctx.client("elbv2")
    rule = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=priority,
        Conditions=[{"Field": "path-pattern", "Values": [path]}],
        Actions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "StatusCode": "200",
                    "ContentType": "text/plain",
                    "MessageBody": path,
                },
            }
        ],
    )["Rules"][0]
    rule_arn = rule["RuleArn"]
    ctx.on_cleanup(lambda: elbv2.delete_rule(RuleArn=rule_arn))
    return rule_arn


# A load balancer, endpoint, cluster, function or instance deletes asynchronously: its ENIs stay
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc
# fails with DependencyViolation. Wait (bounded) for the ENIs to go and retry inside that window.
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
