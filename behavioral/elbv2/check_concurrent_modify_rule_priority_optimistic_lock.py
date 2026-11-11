"""concurrent-modify-rule-priority-optimistic-lock."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-modify-rule-priority-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent SetRulePriorities calls racing for the same numeric priority
    resolve deterministically: exactly one wins, the other is rejected with
    PriorityInUse, and no two rules ever end up sharing a priority."""
    elbv2 = ctx.client("elbv2")
    _vpc_id, subnet_ids = _get_default_vpc_subnets(ctx)
    lb_arn = _create_alb(ctx, subnet_ids)
    listener_arn = _create_listener(ctx, lb_arn, 80, "default-body")

    rule_a = elbv2.create_rule(
        ListenerArn=listener_arn,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/a*"]}}],
        Priority=100,
        Actions=[_fixed_response_action("body-a")],
    )["Rules"][0]["RuleArn"]
    rule_b = elbv2.create_rule(
        ListenerArn=listener_arn,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/b*"]}}],
        Priority=200,
        Actions=[_fixed_response_action("body-b")],
    )["Rules"][0]["RuleArn"]

    # Both concurrent calls target the SAME target priority (1) for two
    # different rules. At most one of them can end up holding priority 1.
    def _set(rule_arn: str) -> tuple[str, Any]:
        try:
            elbv2.set_rule_priorities(RulePriorities=[{"RuleArn": rule_arn, "Priority": 1}])
            return ("ok", None)
        except Exception as exc:  # noqa: BLE001 - we classify by error code below
            message = (getattr(exc, "response", None) or {}).get("Error", {}).get("Message")
            return ("err", _error_code(exc), message)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_set, rule_a)
        fut_b = pool.submit(_set, rule_b)
        result_a = fut_a.result()
        result_b = fut_b.result()

    outcomes = [result_a, result_b]
    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "err"]
    assert len(successes) == 1, f"expected exactly one winner, got {outcomes}"
    assert len(failures) == 1, f"expected exactly one loser, got {outcomes}"
    assert failures[0][1] == "PriorityInUse", f"unexpected loser error code: {failures[0][1]}"
    loser_message = failures[0][2]
    assert loser_message == "One or more priorities not found", loser_message

    rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    priorities = [r["Priority"] for r in rules if not r["IsDefault"]]
    assert len(priorities) == len(set(priorities)), f"duplicate priorities found: {priorities}"
    assert "1" in priorities, f"winner priority 1 missing from final state: {priorities}"
    assert priorities.count("1") == 1, f"expected priority 1 held exactly once, got {priorities}"


def _error_code(exc: Any) -> str | None:
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


def _fixed_response_action(body: str) -> dict[str, Any]:
    return {
        "Type": "fixed-response",
        "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": body},
    }


def _get_default_vpc_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an ALB for this check")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 AZs")
    return vpc_id, subnet_ids


def _create_alb(ctx, subnet_ids: list[str]) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-behav-")[:32]
    lb = elbv2.create_load_balancer(
        Name=name, Subnets=subnet_ids, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_lb_active(ctx, lb_arn)
    return lb_arn


def _wait_lb_active(ctx, lb_arn: str, timeout_s: float = 240.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        if lb["State"]["Code"] == "active":
            return
        if lb["State"]["Code"] == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State']}")
        time.sleep(5)
    raise AssertionError("load balancer never became active in time")


def _create_listener(ctx, lb_arn: str, port: int, default_body: str) -> str:
    elbv2 = ctx.client("elbv2")
    listener = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=port,
        DefaultActions=[_fixed_response_action(default_body)],
    )["Listeners"][0]
    listener_arn = listener["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
