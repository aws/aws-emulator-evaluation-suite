"""enable-aws-network-performance-metric-subscription-contract."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enable-aws-network-performance-metric-subscription-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-network-performance-subscription")
def run(ctx) -> None:
    """EnableAwsNetworkPerformanceMetricSubscription with DryRun fails DryRunOperation with its
    exact message and subscribes nothing; the real call returns Output True and the subscription is
    listed until Disable removes it.
    """
    ec2 = ctx.client("ec2")
    # Not a client region pin: Source/Destination are the Enable call's modeled subject (a
    # cross-Region pair, per AWS's own documented example), independent of ctx.region.
    source, destination, metric, statistic = "us-east-1", "eu-west-1", "aggregate-latency", "p50"

    def _list_subscriptions():
        subs = []
        next_token = None
        while True:
            kwargs = {"NextToken": next_token} if next_token else {}
            resp = ec2.describe_aws_network_performance_metric_subscriptions(**kwargs)
            subs.extend(resp.get("Subscriptions", []))
            next_token = resp.get("NextToken")
            if not next_token:
                return subs

    def _is_subscribed() -> bool:
        return any(
            s.get("Source") == source
            and s.get("Destination") == destination
            and s.get("Metric") == metric
            and s.get("Statistic") == statistic
            for s in _list_subscriptions()
        )

    # Create-or-adopt: normalize to a known-disabled starting state before exercising the
    # contract, so a re-run against an account where a prior run left this pair enabled still
    # gets a meaningful DryRun-must-not-enable assertion below.
    if _is_subscribed():
        ec2.disable_aws_network_performance_metric_subscription(
            Source=source, Destination=destination, Metric=metric, Statistic=statistic,
        )
        assert _poll_until(_is_subscribed, lambda v: v is False, timeout_s=60.0, interval_s=5.0) is False, (
            "could not clear a pre-existing subscription before exercising the contract"
        )

    # NEGATIVE: DryRun must not enable the subscription.
    code, message = _error(lambda: ec2.enable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric=metric, Statistic=statistic, DryRun=True,
    ))
    assert code == "DryRunOperation", f"unexpected DryRun error code: {code}"
    assert message == DRY_RUN_MESSAGE, f"unexpected DryRun message: {message!r}"
    assert _is_subscribed() is False, "DryRun must not actually enable the subscription"

    # POSITIVE: the real call enables the subscription, independently observable via Describe.
    resp = ec2.enable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric=metric, Statistic=statistic,
    )
    assert resp["Output"] is True
    ctx.on_cleanup(lambda: ec2.disable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric=metric, Statistic=statistic,
    ))

    assert _poll_until(_is_subscribed, lambda v: v is True, timeout_s=60.0, interval_s=5.0) is True, (
        "subscription pair never appeared in Describe after enabling"
    )

    # Disable is asserted too: the pair must independently disappear from Describe again.
    ec2.disable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric=metric, Statistic=statistic,
    )
    assert _poll_until(_is_subscribed, lambda v: v is False, timeout_s=60.0, interval_s=5.0) is False, (
        "subscription pair still listed in Describe after disabling"
    )


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
