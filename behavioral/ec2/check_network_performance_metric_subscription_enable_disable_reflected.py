"""network-performance-metric-subscription-enable-disable-reflected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "network-performance-metric-subscription-enable-disable-reflected"
GROUP = "telemetry"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ec2-network-performance-subscription")
def run(ctx) -> None:
    """DescribeAwsNetworkPerformanceMetricSubscriptions lists a subscription
    once Enable has propagated, and stops listing it once Disable has propagated."""
    ec2 = ctx.client("ec2")

    source = ctx.region
    destination = _pick_other_region(ctx, exclude=source)
    metric, statistic = "aggregate-latency", "p50"

    def _is_subscribed() -> bool:
        subs = ec2.describe_aws_network_performance_metric_subscriptions()["Subscriptions"]
        return any(
            s["Source"] == source
            and s["Destination"] == destination
            and s["Metric"] == metric
            and s["Statistic"] == statistic
            for s in subs
        )

    # The subscription is one per account and pair: when the pair is already enabled, take it
    # down for the duration of the check and restore it on cleanup.
    if _is_subscribed():
        ec2.disable_aws_network_performance_metric_subscription(
            Source=source, Destination=destination, Metric=metric, Statistic=statistic
        )
        ctx.on_cleanup(
            lambda: ec2.enable_aws_network_performance_metric_subscription(
                Source=source, Destination=destination, Metric=metric, Statistic=statistic
            )
        )
        _poll_until(_is_subscribed, lambda v: v is False, timeout_s=60)

    ec2.enable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric=metric, Statistic=statistic
    )
    ctx.on_cleanup(
        lambda: ec2.disable_aws_network_performance_metric_subscription(
            Source=source, Destination=destination, Metric=metric, Statistic=statistic
        )
    )

    assert _poll_until(_is_subscribed, lambda v: v is True, timeout_s=60) is True, (
        f"{source}->{destination} {metric}/{statistic} never appeared in Describe after Enable"
    )

    ec2.disable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric=metric, Statistic=statistic
    )

    assert _poll_until(_is_subscribed, lambda v: v is False, timeout_s=60) is False, (
        f"{source}->{destination} {metric}/{statistic} still present in Describe after Disable"
    )


def _pick_other_region(ctx, exclude: str) -> str:
    ec2 = ctx.client("ec2")
    regions = [
        r["RegionName"]
        for r in ec2.describe_regions(AllRegions=False)["Regions"]
        if r["RegionName"] != exclude
    ]
    # Prefer a well-known, always-on Region pair: Infrastructure Performance subscriptions are only
    # reflected in Describe for pairs AWS actually monitors.
    for preferred in ("us-east-1", "us-west-2", "eu-west-1"):
        if preferred in regions:
            return preferred
    return sorted(regions)[0]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
