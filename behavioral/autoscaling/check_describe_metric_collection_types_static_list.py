"""describe-metric-collection-types-static-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-metric-collection-types-static-list"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeMetricCollectionTypes returns every well-known group metric and the
    single supported granularity (1Minute) that EnableMetricsCollection accepts."""
    autoscaling = ctx.client("autoscaling")

    resp = autoscaling.describe_metric_collection_types()
    metrics = {m["Metric"] for m in resp["Metrics"]}
    granularities = {g["Granularity"] for g in resp["Granularities"]}

    expected_metrics = {
        "GroupMinSize",
        "GroupMaxSize",
        "GroupDesiredCapacity",
        "GroupInServiceInstances",
        "GroupPendingInstances",
        "GroupTerminatingInstances",
        "GroupTerminatingRetainedInstances",
        "GroupStandbyInstances",
        "GroupTotalInstances",
        "GroupInServiceCapacity",
        "GroupPendingCapacity",
        "GroupStandbyCapacity",
        "GroupTerminatingCapacity",
        "GroupTerminatingRetainedCapacity",
        "GroupTotalCapacity",
        "WarmPoolMinSize",
        "WarmPoolDesiredCapacity",
        "WarmPoolWarmedCapacity",
        "WarmPoolPendingCapacity",
        "WarmPoolPendingRetainedCapacity",
        "WarmPoolTerminatingCapacity",
        "WarmPoolTerminatingRetainedCapacity",
        "WarmPoolTotalCapacity",
        "GroupAndWarmPoolDesiredCapacity",
        "GroupAndWarmPoolTotalCapacity",
    }
    assert metrics >= expected_metrics, f"missing metrics {expected_metrics - metrics} in {metrics}"
    assert granularities == {"1Minute"}, f"unexpected granularities: {granularities}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
