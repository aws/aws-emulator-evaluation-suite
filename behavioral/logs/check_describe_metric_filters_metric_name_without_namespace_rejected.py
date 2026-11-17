"""describe-metric-filters-metric-name-without-namespace-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-metric-filters-metric-name-without-namespace-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]

_MISSING_NAMESPACE = (
    "InvalidParameterException",
    "Describe Metric Filters request must contain both MetricName and MetricNamespace",
)


def _expect_error(fn, code, message) -> None:
    """Call fn(); assert it raises exactly (code, message). Raises if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected code {code!r}, got {err!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected {code!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeMetricFilters with metricName but neither metricNamespace nor logGroupName
    raises InvalidParameterException with its exact message, while metricName paired with
    metricNamespace finds the real filter."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    filter_name = ctx.unique_name("sim2real-behav-mf-")
    metric_name = "ErrorCount"
    metric_namespace = ctx.unique_name("sim2real/behav/")
    logs.put_metric_filter(
        logGroupName=group,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {"metricName": metric_name, "metricNamespace": metric_namespace, "metricValue": "1"}
        ],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=group, filterName=filter_name))

    # Positive control: metricName paired with its required metricNamespace (and no
    # logGroupName) finds the filter.
    paired = logs.describe_metric_filters(
        metricName=metric_name, metricNamespace=metric_namespace
    )["metricFilters"]
    names = [f["filterName"] for f in paired]
    assert filter_name in names, f"expected {filter_name!r} in {names!r}"

    # Negative: metricName without its required metricNamespace, and without logGroupName
    # either, is rejected.
    _expect_error(lambda: logs.describe_metric_filters(metricName=metric_name), *_MISSING_NAMESPACE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
