"""op-contract-describeAwsNetworkPerformanceMetricSubscriptions."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeAwsNetworkPerformanceMetricSubscriptions"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_METRIC = "aggregate-latency"
_STATISTIC = "p50"
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."
_PERIODS = {"five-minutes", "fifteen-minutes", "one-hour", "three-hours", "one-day", "one-week"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-network-performance-subscription")
def run(ctx) -> None:
    """DescribeAwsNetworkPerformanceMetricSubscriptions lists an enabled subscription with its exact
    Source, Destination, Metric, Statistic and Period and stops listing it once disabled; DryRun
    answers DryRunOperation and lists nothing new."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_aws_network_performance_metric_subscriptions")

    source = ctx.region
    destination = _pick_other_region(ec2, exclude=source)

    def _find():
        subs = ec2.describe_aws_network_performance_metric_subscriptions()["Subscriptions"]
        return next(
            (
                s
                for s in subs
                if s["Source"] == source
                and s["Destination"] == destination
                and s["Metric"] == _METRIC
                and s["Statistic"] == _STATISTIC
            ),
            None,
        )

    # The subscription is one per account and pair: when the pair is already enabled, take it
    # down for the duration of the check and restore it on cleanup.
    if _find() is not None:
        ec2.disable_aws_network_performance_metric_subscription(
            Source=source, Destination=destination, Metric=_METRIC, Statistic=_STATISTIC
        )
        ctx.on_cleanup(
            lambda: ec2.enable_aws_network_performance_metric_subscription(
                Source=source, Destination=destination, Metric=_METRIC, Statistic=_STATISTIC
            )
        )
        _poll_until(_find, lambda s: s is None, timeout_s=60)

    # DryRun on the read itself must refuse with the specific code and must not disturb the listing.
    code, message = _error(
        lambda: ec2.describe_aws_network_performance_metric_subscriptions(DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    assert _find() is None, "a DryRun describe must not itself create a subscription"

    ec2.enable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric=_METRIC, Statistic=_STATISTIC
    )
    ctx.on_cleanup(
        lambda: ec2.disable_aws_network_performance_metric_subscription(
            Source=source, Destination=destination, Metric=_METRIC, Statistic=_STATISTIC
        )
    )

    found = _poll_until(_find, lambda s: s is not None, timeout_s=60)
    assert found["Source"] == source
    assert found["Destination"] == destination
    assert found["Metric"] == _METRIC
    assert found["Statistic"] == _STATISTIC
    assert found["Period"] in _PERIODS, f"unexpected Period {found.get('Period')!r}"

    ec2.disable_aws_network_performance_metric_subscription(
        Source=source, Destination=destination, Metric=_METRIC, Statistic=_STATISTIC
    )
    assert _poll_until(_find, lambda s: s is None, timeout_s=60) is None


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _pick_other_region(ec2, exclude: str) -> str:
    regions = [
        r["RegionName"]
        for r in ec2.describe_regions(AllRegions=False)["Regions"]
        if r["RegionName"] != exclude
    ]
    if not regions:
        raise AssertionError("no second enabled Region available to form a source/destination pair")
    # Infrastructure Performance carries data only between certain region pairs, so prefer the pairing
    # the AWS docs use, in this order among the discovered regions.
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
