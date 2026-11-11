"""create-rule-same-priority-concurrent-single-winner."""
from __future__ import annotations

import concurrent.futures
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-rule-same-priority-concurrent-single-winner"
GROUP = "state-machine"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateRule calls with the same Priority on one listener: exactly one wins and is the
    only rule at that priority in DescribeRules; every other racer gets PriorityInUse."""
    elbv2 = ctx.client("elbv2")
    vpc_id, subnet_ids = _setup_network(ctx)
    lb_arn = _create_alb(ctx, subnet_ids)
    tg_arn = _create_target_group(ctx, vpc_id)

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=_tags_kv(ctx),
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    priority = 137
    racer_count = 8

    def _race(i: int):
        try:
            rule_arn = elbv2.create_rule(
                ListenerArn=listener_arn,
                Priority=priority,
                Conditions=[{"Field": "path-pattern", "Values": [f"/race-{i}/*"]}],
                Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
                Tags=_tags_kv(ctx),
            )["Rules"][0]["RuleArn"]
            return ("ok", rule_arn)
        except Exception as exc:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            raise

    with concurrent.futures.ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_race, range(racer_count)))

    wins = [r for r in results if r[0] == "ok"]
    losses = [r for r in results if r[0] == "error"]

    assert len(wins) == 1, f"expected exactly 1 winner, got {len(wins)} (results={results})"
    assert len(losses) == racer_count - 1, f"expected {racer_count - 1} losers, got {len(losses)}"
    assert all(code == "PriorityInUse" for _, code, _m in losses), f"unexpected loser codes: {losses}"
    for _, _code, message in losses:
        assert message == f"Priority '{priority}' is currently in use", message

    winning_rule_arn = wins[0][1]
    ctx.on_cleanup(lambda: elbv2.delete_rule(RuleArn=winning_rule_arn))

    rules_at_priority = [
        r
        for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
        if not r["IsDefault"] and r["Priority"] == str(priority)
    ]
    assert len(rules_at_priority) == 1, (
        f"expected exactly 1 rule at priority {priority} post-race, got {len(rules_at_priority)} "
        f"(rules={rules_at_priority})"
    )
    assert rules_at_priority[0]["RuleArn"] == winning_rule_arn, (
        f"expected the surviving rule at priority {priority} to be the race winner "
        f"{winning_rule_arn}, got {rules_at_priority[0]['RuleArn']}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _tags_kv(ctx):
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:check", "Value": CHECK},
    ]


def _setup_network(ctx, num_subnets=2):
    """Create-or-adopt: use the default VPC if it spans enough AZs, else create our own --
    a freshly provisioned account may have no default VPC at all."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az: dict[str, str] = {}
        for s in sorted(subnets, key=lambda s: s["SubnetId"]):
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= num_subnets:
            return vpc_id, list(by_az.values())[:num_subnets]

    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv(ctx))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    if len(azs) < num_subnets:
        raise AssertionError(f"region has fewer than {num_subnets} available availability zones")
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        ec2.create_tags(Resources=[sid], Tags=_tags_kv(ctx))
    return vpc_id, subnet_ids


def _create_alb(ctx, subnet_ids) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-lb-race-")[:32]
    lb = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Type="application", Scheme="internal", Tags=_tags_kv(ctx)
    )["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]

    def _cleanup():
        try:
            elbv2.delete_load_balancer(LoadBalancerArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code in ("active", "active_impaired"),
        timeout_s=180,
        interval_s=5,
    )
    return arn


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-tg-race-")[:32]
    tg = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip", Tags=_tags_kv(ctx)
    )["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=arn))
    return arn


# Teardown waits (bounded) for AWS-managed ENIs to leave: a load balancer, endpoint, cluster or
# instance in this VPC deletes asynchronously and its ENIs linger, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Retry that inside one window shared
# by all of a check's network deletes, then raise naming the ENIs still attached.
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
