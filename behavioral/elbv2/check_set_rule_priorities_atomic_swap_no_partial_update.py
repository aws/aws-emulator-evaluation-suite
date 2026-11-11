"""set-rule-priorities-atomic-swap-no-partial-update."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "set-rule-priorities-atomic-swap-no-partial-update"
GROUP = "ordering"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetRulePriorities swaps two rules' priorities as one batch, each swap landing whole,
    and a batch that names an unknown rule fails without applying any of its entries."""
    elbv2 = ctx.client("elbv2")
    lb_arn = _create_alb(ctx)
    listener_arn = _create_listener(ctx, lb_arn)
    prio_a, prio_b = 15, 25
    rule_a = _create_rule(ctx, listener_arn, prio_a, "/rule-a*")
    rule_b = _create_rule(ctx, listener_arn, prio_b, "/rule-b*")

    def priorities() -> dict[str, int]:
        rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
        return {r["RuleArn"]: int(r["Priority"]) for r in rules if not r.get("IsDefault")}

    for i in range(15):
        if i % 2 == 0:
            new_a, new_b = prio_b, prio_a
        else:
            new_a, new_b = prio_a, prio_b
        elbv2.set_rule_priorities(
            RulePriorities=[
                {"RuleArn": rule_a, "Priority": new_a},
                {"RuleArn": rule_b, "Priority": new_b},
            ]
        )
        seen = priorities()
        assert (seen[rule_a], seen[rule_b]) == (new_a, new_b), (
            f"swap {i}: expected priorities ({new_a}, {new_b}), got ({seen[rule_a]}, {seen[rule_b]})"
        )

    before = priorities()
    missing_rule = rule_a.rsplit("/", 1)[0] + "/0000000000000000"
    try:
        elbv2.set_rule_priorities(
            RulePriorities=[
                {"RuleArn": rule_a, "Priority": 35},
                {"RuleArn": missing_rule, "Priority": 45},
            ]
        )
    except ClientError:
        pass
    else:
        raise AssertionError("SetRulePriorities with an unknown rule ARN in the batch succeeded")
    after = priorities()
    assert after == before, (
        f"failed SetRulePriorities batch partially applied: before {before}, after {after}"
    )

    final = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    final_map = {r["RuleArn"]: r["Priority"] for r in final if not r.get("IsDefault")}
    assert final_map[rule_a] != final_map[rule_b], "rules ended up sharing a priority"
    final_prios = {int(final_map[rule_a]), int(final_map[rule_b])}
    assert final_prios == {prio_a, prio_b}, (
        f"expected final priorities {{{prio_a}, {prio_b}}}, got {final_prios}"
    )


def _get_alb_network(ctx) -> tuple[str, list[str], str | None]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    chosen = list(by_az.values())[:2]
    if len(chosen) < 2:
        raise AssertionError("need subnets in at least 2 distinct AZs to create a load balancer")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return vpc_id, [s["SubnetId"] for s in chosen], sg_id


def _alb_name(ctx, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:32].rstrip("-")


def _create_alb(ctx) -> str:
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids, sg_id = _get_alb_network(ctx)
    kwargs: dict[str, Any] = dict(
        Name=_alb_name(ctx, "ord"),
        Subnets=subnet_ids,
        Type="application",
        Scheme="internet-facing",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
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
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
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
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Rules"][0]
    rule_arn = rule["RuleArn"]
    ctx.on_cleanup(lambda: elbv2.delete_rule(RuleArn=rule_arn))
    return rule_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
