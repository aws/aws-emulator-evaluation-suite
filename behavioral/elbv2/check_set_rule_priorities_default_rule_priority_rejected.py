"""set-rule-priorities-default-rule-priority-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "set-rule-priorities-default-rule-priority-rejected"
GROUP = "ordering"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetRulePriorities cannot assign a numbered priority to a listener's default
    rule -- the API rejects it with OperationNotPermittedException instead of
    silently reordering the default action into the priority chain."""
    elbv2 = ctx.client("elbv2")
    lb_arn = _create_alb(ctx)
    listener_arn = _create_listener(ctx, lb_arn)

    listener = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]
    default_rule_arn = None
    for rule in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]:
        if rule.get("IsDefault"):
            default_rule_arn = rule["RuleArn"]
            break
    assert default_rule_arn, "expected exactly one default rule on a freshly created listener"
    del listener

    # Positive control: SetRulePriorities succeeds on an ordinary (non-default)
    # rule, proving the call path works on this target before the default-rule
    # refusal is exercised -- otherwise "rejects the default rule" would be
    # indistinguishable from "rejects every SetRulePriorities call".
    control_rule_arn = _create_rule(ctx, listener_arn, 7, "/sim2real-ord4-control*")
    elbv2.set_rule_priorities(RulePriorities=[{"RuleArn": control_rule_arn, "Priority": 15}])
    control_after_control = elbv2.describe_rules(RuleArns=[control_rule_arn])["Rules"][0]
    assert control_after_control["Priority"] == "15", (
        f"positive control failed: expected the ordinary rule's priority to become '15', "
        f"got {control_after_control['Priority']!r}"
    )

    code, message = _error(
        lambda: elbv2.set_rule_priorities(RulePriorities=[{"RuleArn": default_rule_arn, "Priority": 5}])
    )
    # The wire code omits the "Exception" suffix of botocore's shape name.
    assert code == "OperationNotPermitted", (
        f"expected OperationNotPermittedException when setting a priority on the default rule, got {code}"
    )
    expected_message = "The priority of a default rule cannot be changed"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    default_after = [r for r in rules if r.get("IsDefault")]
    assert len(default_after) == 1 and default_after[0]["RuleArn"] == default_rule_arn, (
        "default rule identity/priority changed despite a rejected SetRulePriorities call"
    )
    control_final = next(r for r in rules if r["RuleArn"] == control_rule_arn)
    assert control_final["Priority"] == "15", (
        f"control rule priority drifted after the rejected default-rule call: "
        f"{control_final['Priority']!r}"
    )


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


def _tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]


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
        Name=_alb_name(ctx, "ord4"),
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
        Tags=_tags_kv(),
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
        Tags=_tags_kv(),
    )["Rules"][0]
    rule_arn = rule["RuleArn"]
    ctx.on_cleanup(lambda: elbv2.delete_rule(RuleArn=rule_arn))
    return rule_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
