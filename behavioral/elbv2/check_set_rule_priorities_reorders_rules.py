"""set-rule-priorities-reorders-rules."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-rule-priorities-reorders-rules"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRulePriorities swaps two rules' priorities and DescribeRules reflects the new
    priority-to-condition mapping."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    tg = _create_target_group(ctx, net["vpc_id"])

    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
    )["Listeners"][0]
    # Delete the listener before the target group: its DefaultActions still reference
    # tg's ARN, and DeleteTargetGroup rejects with ResourceInUse while that reference lives.
    # LIFO cleanup order otherwise runs tg's delete (registered in _create_target_group,
    # before the listener existed) ahead of the load balancer's, leaking the target group.
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_listener(ListenerArn=listener["ListenerArn"])))

    rule_a = elbv2.create_rule(
        ListenerArn=listener["ListenerArn"],
        Priority=1,
        Conditions=[{"Field": "path-pattern", "Values": ["/a/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        Tags=_tags_kv(),
    )["Rules"][0]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_rule(RuleArn=rule_a["RuleArn"])))

    rule_b = elbv2.create_rule(
        ListenerArn=listener["ListenerArn"],
        Priority=2,
        Conditions=[{"Field": "path-pattern", "Values": ["/b/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}],
        Tags=_tags_kv(),
    )["Rules"][0]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_rule(RuleArn=rule_b["RuleArn"])))

    swapped = elbv2.set_rule_priorities(
        RulePriorities=[
            {"RuleArn": rule_a["RuleArn"], "Priority": 2},
            {"RuleArn": rule_b["RuleArn"], "Priority": 1},
        ]
    )["Rules"]
    by_arn = {r["RuleArn"]: r for r in swapped}
    assert by_arn[rule_a["RuleArn"]]["Priority"] == "2", by_arn
    assert by_arn[rule_b["RuleArn"]]["Priority"] == "1", by_arn

    described = elbv2.describe_rules(ListenerArn=listener["ListenerArn"])["Rules"]
    by_priority = {r["Priority"]: r["Conditions"][0]["Values"] for r in described if not r["IsDefault"]}
    assert by_priority["1"] == ["/b/*"], by_priority
    assert by_priority["2"] == ["/a/*"], by_priority


# ===== helpers =====
# Not-found codes a teardown treats as already deleted; an in-use target group is retried.
_GONE = frozenset({
    "ListenerNotFound", "RuleNotFound", "TargetGroupNotFound", "LoadBalancerNotFound",
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
})


def _safe(fn):
    """Run one teardown call: a resource already gone is fine; one still held by a deleting load
    balancer (ResourceInUse) is retried every 2 s for up to 180 s; any other error raises."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in _GONE:
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-elbv2"}]


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s)
        if len(by_az) >= 2:
            chosen = list(by_az.values())[:2]
            return {"vpc_id": vpc_id, "subnet_ids": [s["SubnetId"] for s in chosen]}

    # No usable default VPC (or too few AZs) — create a minimal one instead of failing.
    vpc_id = ec2.create_vpc(CidrBlock="10.90.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=_tags_kv())
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError("region does not have at least 2 available availability zones")
    subnet_ids = []
    for i in range(2):
        az = azs[i]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.90.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        ec2.create_tags(Resources=[sid], Tags=_tags_kv())
        subnet_ids.append(sid)
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
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_target_group(TargetGroupArn=arn)))
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
