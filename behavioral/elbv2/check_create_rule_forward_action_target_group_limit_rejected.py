"""create-rule-forward-action-target-group-limit-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rule-forward-action-target-group-limit-rejected"
GROUP = "listener-rule-validation"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRule rejects a forward action listing more than 5 target groups.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html
    """
    elbv2 = ctx.client("elbv2")
    net = ctx.network()
    tg_arns = [_create_target_group(ctx, net.vpc_id) for _ in range(6)]
    lb_arn = _create_internal_alb(ctx, net.subnet_ids, [net.security_group_id])
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arns[0]}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    # Positive control: a forward action naming exactly 5 target groups (the documented limit) is
    # accepted.
    allowed_rule = elbv2.create_rule(
        ListenerArn=listener_arn,
        Conditions=[{"Field": "path-pattern", "Values": ["/allowed"]}],
        Priority=5,
        Actions=[{
            "Type": "forward",
            "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": a, "Weight": 1} for a in tg_arns[:5]]},
        }],
    )["Rules"][0]
    ctx.on_cleanup(lambda: elbv2.delete_rule(RuleArn=allowed_rule["RuleArn"]))

    code, message = _error(lambda: elbv2.create_rule(
        ListenerArn=listener_arn,
        Conditions=[{"Field": "path-pattern", "Values": ["/rejected"]}],
        Priority=6,
        Actions=[{
            "Type": "forward",
            "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": a, "Weight": 1} for a in tg_arns]},
        }],
    ))
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == "You cannot specify more than 5 target groups per action", f"MESSAGE={message!r}"

    # The 6-target-group rule never materialized: only the allowed rule and the listener's
    # synthetic default rule exist on this listener.
    rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    priorities = {r["Priority"] for r in rules}
    assert priorities == {"5", "default"}, f"expected priorities {{5, default}}, got {priorities!r}"


# ===== helpers =====

_THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "RequestThrottled", "TooManyRequestsException",
})


def _error(fn, attempts: int = 5):
    """Return the refusal's ``(code, message)``; an unexpected SUCCESS raises."""
    delays = [3, 6, 12, 24, 30]
    for attempt in range(attempts):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") not in _THROTTLE_CODES:
                return err.get("Code"), err.get("Message")
            time.sleep(delays[min(attempt, len(delays) - 1)])
            continue
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")
    raise AssertionError(f"still throttled after {attempts} attempts")


def _create_target_group(ctx, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-tg-"), Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="ip",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))
    return tg_arn


def _create_internal_alb(ctx, subnet_ids, sg_ids) -> str:
    elbv2 = ctx.client("elbv2")
    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-alb-"), Subnets=subnet_ids, SecurityGroups=sg_ids,
        Scheme="internal", Type="application",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn))
    _wait_for_active(elbv2, lb_arn)
    return lb_arn


def _wait_for_active(elbv2, lb_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        code = lb["State"]["Code"]
        if code == "active":
            return lb
        if code == "failed":
            raise AssertionError(f"load balancer entered failed state: {lb['State'].get('Reason')}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"load balancer did not reach active within {timeout_s}s (last state {code!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
