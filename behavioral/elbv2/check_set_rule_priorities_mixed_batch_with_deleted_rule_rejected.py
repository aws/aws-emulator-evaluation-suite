"""set-rule-priorities-mixed-batch-with-deleted-rule-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-rule-priorities-mixed-batch-with-deleted-rule-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]

_RULE_NOT_FOUND = ("RuleNotFound", "One or more rules not found")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetRulePriorities naming a deleted rule's RuleArn is refused RuleNotFound, whether it is
    the only entry or paired with a live rule's move; a mixed batch leaves the live rule's
    priority untouched, and moving only the live rule afterwards succeeds.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_SetRulePriorities.html
    """
    elb = ctx.client("elbv2")
    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    assert len(subnet_ids) >= 2, f"the run's network has {len(net.subnet_ids)} subnet(s), an ALB needs two"

    lb_name = ctx.unique_name("sim2real-behav-lb-")[:32].rstrip("-")
    lb = elb.create_load_balancer(
        Name=lb_name, Subnets=subnet_ids, Type="application", Scheme="internal",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elb.delete_load_balancer(LoadBalancerArn=lb_arn))

    tg_name = ctx.unique_name("sim2real-behav-tg-")[:32].rstrip("-")
    tg = elb.create_target_group(
        Name=tg_name, Protocol="HTTP", Port=80, TargetType="ip", VpcId=net.vpc_id,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elb.delete_target_group(TargetGroupArn=tg_arn))

    listener = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=listener_arn))

    live_arn = elb.create_rule(
        ListenerArn=listener_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/live/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=live_arn))

    deleted_arn = elb.create_rule(
        ListenerArn=listener_arn, Priority=20,
        Conditions=[{"Field": "path-pattern", "Values": ["/gone/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Rules"][0]["RuleArn"]
    elb.delete_rule(RuleArn=deleted_arn)

    def _rules_by_arn():
        rules = elb.describe_rules(ListenerArn=listener_arn)["Rules"]
        return {r["RuleArn"]: r for r in rules if not r.get("IsDefault")}

    expect_error(
        lambda: elb.set_rule_priorities(
            RulePriorities=[{"RuleArn": deleted_arn, "Priority": 30}]
        ),
        *_RULE_NOT_FOUND,
    )
    after_solo = _rules_by_arn()
    assert set(after_solo) == {live_arn}, (
        f"a refused solo move must leave no trace of the deleted rule: {sorted(after_solo)}"
    )
    assert after_solo[live_arn]["Priority"] == "10", (
        f"a refused solo move must not touch the live rule's priority, got {after_solo[live_arn]['Priority']!r}"
    )

    expect_error(
        lambda: elb.set_rule_priorities(
            RulePriorities=[
                {"RuleArn": live_arn, "Priority": 40},
                {"RuleArn": deleted_arn, "Priority": 30},
            ]
        ),
        *_RULE_NOT_FOUND,
    )
    after_mixed = _rules_by_arn()
    assert set(after_mixed) == {live_arn}, (
        f"a refused mixed batch must leave no trace of the deleted rule: {sorted(after_mixed)}"
    )
    assert after_mixed[live_arn]["Priority"] == "10", (
        "a refused mixed batch must not apply its live-rule entry either, got "
        f"{after_mixed[live_arn]['Priority']!r}"
    )

    moved = elb.set_rule_priorities(
        RulePriorities=[{"RuleArn": live_arn, "Priority": 40}]
    )["Rules"]
    assert moved[0]["Priority"] == "40", (
        f"positive control: moving only the live rule must succeed, got {moved[0]!r}"
    )
    final = _rules_by_arn()
    assert final[live_arn]["Priority"] == "40", (
        f"DescribeRules must show the live rule's new priority, got {final[live_arn]['Priority']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
