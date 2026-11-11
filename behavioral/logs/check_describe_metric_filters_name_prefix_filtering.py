"""describe-metric-filters-name-prefix-filtering."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-metric-filters-name-prefix-filtering"
GROUP = "telemetry"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeMetricFilters filterNamePrefix returns only the filters on the log
    group whose name matches the prefix, excluding sibling filters that don't."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-logs-mfprefix-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    names = ["alpha-one", "alpha-two", "beta-one"]
    for name in names:
        logs.put_metric_filter(
            logGroupName=log_group,
            filterName=name,
            filterPattern="ERROR",
            metricTransformations=[
                {"metricName": f"Metric-{name}", "metricNamespace": "Sim2RealPrefix", "metricValue": "1"}
            ],
        )

    # Sanity: with no prefix, all three come back.
    all_filters = logs.describe_metric_filters(logGroupName=log_group)["metricFilters"]
    all_names = {f["filterName"] for f in all_filters}
    assert all_names == set(names), f"expected all three filters with no prefix, got {all_names}"

    prefixed = logs.describe_metric_filters(logGroupName=log_group, filterNamePrefix="alpha-")[
        "metricFilters"
    ]
    prefixed_names = {f["filterName"] for f in prefixed}
    assert prefixed_names == {"alpha-one", "alpha-two"}, (
        f"expected only alpha-* filters, got {prefixed_names}"
    )
    assert "beta-one" not in prefixed_names, (
        f"filterNamePrefix='alpha-' must exclude sibling filters, got {prefixed_names}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
