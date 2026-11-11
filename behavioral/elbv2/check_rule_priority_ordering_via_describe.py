"""rule-priority-ordering-via-describe."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rule-priority-ordering-via-describe"
GROUP = "data-plane"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Rules created with distinct priorities and conditions are all visible via DescribeRules,
    returned in ascending-priority order regardless of creation order, alongside the listener's
    implicit default rule sorted last."""
    net = _default_vpc_and_subnets(ctx)
    elbv2 = ctx.client("elbv2")
    lb = _create_alb(ctx, net["subnet_ids"])
    tg1 = _create_target_group(ctx, net["vpc_id"])
    tg2 = _create_target_group(ctx, net["vpc_id"])

    listener = elbv2.create_listener(
        LoadBalancerArn=lb["LoadBalancerArn"],
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg1["TargetGroupArn"]}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]

    # Created out of priority order (20 before 10) so a target that merely echoes creation
    # order, rather than sorting by priority, is distinguishable from a correct one.
    rule_b = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=20,
        Conditions=[{"Field": "path-pattern", "Values": ["/static/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg1["TargetGroupArn"]}],
    )["Rules"][0]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_rule(RuleArn=rule_b["RuleArn"])))

    rule_a = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/api/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg2["TargetGroupArn"]}],
    )["Rules"][0]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_rule(RuleArn=rule_a["RuleArn"])))

    rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    by_priority = {r["Priority"]: r for r in rules}

    assert "default" in by_priority, f"default rule missing: {sorted(by_priority.keys())}"
    assert by_priority["default"]["IsDefault"] is True, (
        f"default rule IsDefault flag not True: {by_priority['default']}"
    )

    assert "10" in by_priority, f"priority-10 rule missing from DescribeRules: {sorted(by_priority.keys())}"
    assert by_priority["10"]["IsDefault"] is False, (
        f"priority-10 rule wrongly flagged IsDefault: {by_priority['10']}"
    )
    assert by_priority["10"]["Conditions"][0]["Values"] == ["/api/*"], (
        f"expected /api/* condition on priority 10, got {by_priority['10']['Conditions']}"
    )
    assert by_priority["10"]["Actions"][0]["TargetGroupArn"] == tg2["TargetGroupArn"], (
        f"expected priority 10 to forward to {tg2['TargetGroupArn']}, got {by_priority['10']['Actions']}"
    )

    assert "20" in by_priority, f"priority-20 rule missing from DescribeRules: {sorted(by_priority.keys())}"
    assert by_priority["20"]["Conditions"][0]["Values"] == ["/static/*"], (
        f"expected /static/* condition on priority 20, got {by_priority['20']['Conditions']}"
    )

    assert len(rules) == 3, f"expected default + 2 custom rules, got {len(rules)}: {rules}"

    # The actual subject of this check: DescribeRules' returned *order*, not just membership.
    # rule_b (priority 20) was created before rule_a (priority 10); the list must still come
    # back sorted ascending by priority, with the default rule (evaluated last) sorted last.
    observed_priorities = [int(r["Priority"]) for r in rules if not r["IsDefault"]]
    assert observed_priorities == sorted(observed_priorities), (
        f"DescribeRules did not return ascending-priority order despite reverse creation "
        f"order: {observed_priorities}"
    )
    assert rules[-1]["IsDefault"] is True, (
        f"default rule must sort last (evaluated last), got order: {[r['Priority'] for r in rules]}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "LoadBalancerNotFound",
            "RuleNotFound",
            "TargetGroupNotFound",
        ):
            raise


def _default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 availability zones")
    chosen = list(by_az.values())[:2]
    return {
        "vpc_id": vpc_id,
        "subnet_ids": [s["SubnetId"] for s in chosen],
        "subnet_cidrs": [s["CidrBlock"] for s in chosen],
    }


def _create_alb(ctx, subnet_ids, name=None):
    elbv2 = ctx.client("elbv2")
    name = name or ctx.unique_name("sim2real-elbv2-lb-")
    resp = elbv2.create_load_balancer(Name=name, Subnets=subnet_ids, Type="application")
    lb = resp["LoadBalancers"][0]
    arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=arn)))
    return lb


def _create_target_group(ctx, vpc_id, **kwargs):
    elbv2 = ctx.client("elbv2")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-elbv2-tg-")
    params = {"Name": name, "Protocol": "HTTP", "Port": 80, "VpcId": vpc_id, "TargetType": "ip"}
    params.update(kwargs)
    resp = elbv2.create_target_group(**params)
    tg = resp["TargetGroups"][0]
    arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _safe(lambda: elbv2.delete_target_group(TargetGroupArn=arn)))
    return tg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
