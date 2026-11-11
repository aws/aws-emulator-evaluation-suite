"""set-rule-priorities-duplicate-priority-fails."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "set-rule-priorities-duplicate-priority-fails"
GROUP = "ordering"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetRulePriorities onto a priority another rule holds fails with PriorityInUse and the exact message and moves
    neither rule, while moves onto free priorities apply, including the same move once the priority is freed."""
    elbv2 = ctx.client("elbv2")
    lb_arn = _create_alb(ctx)
    listener_arn = _create_listener(ctx, lb_arn)
    rule_a = _create_rule(ctx, listener_arn, 10, "/dup-a*")
    rule_b = _create_rule(ctx, listener_arn, 20, "/dup-b*")

    # Positive control: moving rule_b onto a free priority succeeds.
    elbv2.set_rule_priorities(RulePriorities=[{"RuleArn": rule_b, "Priority": 15}])
    priorities = _read_priorities(elbv2, listener_arn)
    assert priorities[rule_b] == "15", f"positive control did not move rule_b to 15: {priorities}"

    code, message = _error(
        lambda: elbv2.set_rule_priorities(RulePriorities=[{"RuleArn": rule_b, "Priority": 10}])
    )
    # The wire code omits the "Exception" suffix of botocore's shape name.
    assert code == "PriorityInUse", (
        f"expected PriorityInUseException, got {code}"
    )
    expected_message = "One or more priorities not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    priorities = _read_priorities(elbv2, listener_arn)
    assert priorities[rule_a] == "10" and priorities[rule_b] == "15", (
        f"priorities changed despite a rejected SetRulePriorities call: {priorities}"
    )

    # Restore: free priority 10 by moving rule_a off it, then the identical
    # rule_b -> 10 request must now succeed.
    elbv2.set_rule_priorities(RulePriorities=[{"RuleArn": rule_a, "Priority": 30}])
    elbv2.set_rule_priorities(RulePriorities=[{"RuleArn": rule_b, "Priority": 10}])
    priorities = _read_priorities(elbv2, listener_arn)
    assert priorities[rule_a] == "30" and priorities[rule_b] == "10", (
        f"identical SetRulePriorities call did not succeed once priority 10 was freed: {priorities}"
    )


def _read_priorities(elbv2, listener_arn: str) -> dict[str, str]:
    return {
        r["RuleArn"]: r["Priority"]
        for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
        if not r.get("IsDefault")
    }


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
        Name=_alb_name(ctx, "ord3"),
        Subnets=subnet_ids,
        Type="application",
        Scheme="internet-facing",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
