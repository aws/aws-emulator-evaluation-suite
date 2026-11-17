"""describe-rules-without-listener-or-rule-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-rules-without-listener-or-rule-arn-rejected"
GROUP = "listener-rule-validation"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeRules with neither ListenerArn nor RuleArns rejects as a validation error.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeRules.html
    """
    elbv2 = ctx.client("elbv2")
    net = ctx.network()
    tg_arn = _create_target_group(ctx, net.vpc_id)
    lb_arn = _create_internal_alb(ctx, net.subnet_ids, [net.security_group_id])
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    # Positive control: a valid lookup by ListenerArn returns the listener's default rule.
    before = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    assert len(before) == 1 and before[0]["IsDefault"], (
        f"expected exactly the synthetic default rule, got {before!r}"
    )

    code, message = _error(lambda: elbv2.describe_rules())
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == "You must specify either listener rule ARNs or a listener ARN", f"MESSAGE={message!r}"

    # The identical valid lookup still succeeds: the rejected call left no mark on the listener.
    after = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    assert after == before, f"expected the rule list unchanged, got {after!r} (was {before!r})"


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
