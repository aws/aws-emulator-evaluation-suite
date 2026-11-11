"""network-performance-subscription-invalid-region-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-performance-subscription-invalid-region-rejected"
GROUP = "telemetry"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-network-performance-subscription")
def run(ctx) -> None:
    """EnableAwsNetworkPerformanceMetricSubscription with a Statistic outside the p50-only enum
    fails InvalidParameter with its exact message and subscribes nothing, while the same call with
    p50 succeeds.
    """
    ec2 = ctx.client("ec2")

    source = ctx.region
    destination = _pick_other_region(ctx, exclude=source)
    bogus_statistic = "p99"

    def _is_subscribed(statistic: str) -> bool:
        subs = ec2.describe_aws_network_performance_metric_subscriptions()["Subscriptions"]
        return any(
            s["Source"] == source
            and s["Destination"] == destination
            and s["Metric"] == "aggregate-latency"
            and s["Statistic"] == statistic
            for s in subs
        )

    # The p50 subscription is one per account and pair: when the pair is already enabled, take it
    # down for the duration of the check and restore it on cleanup.
    if _is_subscribed("p50"):
        ec2.disable_aws_network_performance_metric_subscription(
            Source=source, Destination=destination, Metric="aggregate-latency", Statistic="p50"
        )
        ctx.on_cleanup(
            lambda: ec2.enable_aws_network_performance_metric_subscription(
                Source=source, Destination=destination, Metric="aggregate-latency", Statistic="p50"
            )
        )
        _poll_until(lambda: _is_subscribed("p50"), lambda v: v is False, timeout_s=60)

    try:
        result = ec2.enable_aws_network_performance_metric_subscription(
            Source=source,
            Destination=destination,
            Metric="aggregate-latency",
            Statistic=bogus_statistic,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"expected Statistic={bogus_statistic!r} to be rejected, but it SUCCEEDED: {result!r}")
    assert code == "InvalidParameter", f"expected InvalidParameter for Statistic={bogus_statistic!r}, got {code!r}"
    assert message == f"Invalid value for Statistic: {bogus_statistic} Valid values are: [p50]", message

    # Effect absent: no subscription for the bogus statistic was created.
    assert _is_subscribed(bogus_statistic) is False, (
        f"a subscription for the rejected Statistic={bogus_statistic!r} should not exist"
    )

    # Positive control: the only supported statistic value is accepted.
    ec2.enable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric="aggregate-latency", Statistic="p50"
    )
    ctx.on_cleanup(
        lambda: ec2.disable_aws_network_performance_metric_subscription(
            Source=source,
            Destination=destination,
            Metric="aggregate-latency",
            Statistic="p50",
        )
    )
    assert _poll_until(lambda: _is_subscribed("p50"), lambda v: v is True, timeout_s=60) is True, (
        "expected the p50 subscription to be visible after the positive control"
    )


def _pick_other_region(ctx, exclude: str) -> str:
    ec2 = ctx.client("ec2")
    regions = [
        r["RegionName"]
        for r in ec2.describe_regions(AllRegions=False)["Regions"]
        if r["RegionName"] != exclude
    ]
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
