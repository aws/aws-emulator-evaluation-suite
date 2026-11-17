"""create-rule-forward-target-groups-exceeding-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rule-forward-target-groups-exceeding-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]


def _teardown(undo, *not_found: str):
    """Run ``undo()``; a failed delete raises unless its code is one of ``not_found``."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _refused(fn):
    """The (code, message) ``fn`` is refused with. Raises, naming the result, on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the rule to be refused, but it was created: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRule refuses a forward action naming six target groups with the exact over-limit
    error, creating no rule, while five target groups at the same priority are accepted and
    listed with their weights."""
    elbv2 = ctx.client("elbv2")
    net = ctx.network()
    subnets = net.subnet_ids[:2]
    assert len(subnets) == 2, f"the run's network has {len(subnets)} subnet(s), an ALB needs two"

    lb_name = ctx.unique_name("sim2real-tgactlim-")[:32].rstrip("-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=subnets, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn), "LoadBalancerNotFound"))
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{
            "Type": "fixed-response",
            "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"},
        }],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_listener(ListenerArn=listener_arn), "ListenerNotFound"))

    tg_arns = []
    for i in range(6):
        tg_name = ctx.unique_name(f"sim2real-tgactlim-{i}-")[:32].rstrip("-")
        tg_arn = elbv2.create_target_group(
            Name=tg_name, Protocol="HTTP", Port=80, VpcId=net.vpc_id, TargetType="ip",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["TargetGroups"][0]["TargetGroupArn"]
        tg_arns.append(tg_arn)
        ctx.on_cleanup(_teardown(lambda arn=tg_arn: elbv2.delete_target_group(TargetGroupArn=arn), "TargetGroupNotFound"))

    def forward_action(arns):
        return [{
            "Type": "forward",
            "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": a, "Weight": 1} for a in arns]},
        }]

    over_limit_condition = [{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/over"]}}]
    code, message = _refused(lambda: elbv2.create_rule(
        ListenerArn=listener_arn, Priority=1, Conditions=over_limit_condition,
        Actions=forward_action(tg_arns),
    ))
    assert code == "ValidationError", f"expected ValidationError for six target groups, got {code!r}"
    expected_message = "You cannot specify more than 5 target groups per action"
    assert message == expected_message, f"MSG={message!r}"

    rules_at_priority_1 = [
        r for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"] if r["Priority"] == "1"
    ]
    assert rules_at_priority_1 == [], f"a rule exists at priority 1 after the refusal: {rules_at_priority_1!r}"

    in_limit_condition = [{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/ok"]}}]
    ok = elbv2.create_rule(
        ListenerArn=listener_arn, Priority=1, Conditions=in_limit_condition,
        Actions=forward_action(tg_arns[:5]),
    )["Rules"][0]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_rule(RuleArn=ok["RuleArn"]), "RuleNotFound"))
    echoed = {tg["TargetGroupArn"] for tg in ok["Actions"][0]["ForwardConfig"]["TargetGroups"]}
    assert echoed == set(tg_arns[:5]), f"the five-target-group rule echoed {echoed!r}, expected {set(tg_arns[:5])!r}"

    rules_at_priority_1 = [
        r for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"] if r["Priority"] == "1"
    ]
    assert [r["RuleArn"] for r in rules_at_priority_1] == [ok["RuleArn"]], (
        f"expected exactly the accepted rule at priority 1, got {rules_at_priority_1!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
