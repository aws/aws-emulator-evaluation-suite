"""put-metric-filter-nonexistent-log-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-filter-nonexistent-log-group-rejected"
GROUP = "telemetry"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricFilter and DescribeMetricFilters on a nonexistent log group get ResourceNotFoundException
    and its exact message and create no filter, while the same Put on a real group creates it.
    """
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-logs-mfneg2-")
    bogus_log_group = ctx.unique_name("sim2real-logs-mfneg2-missing-")
    filter_name = ctx.unique_name("sim2real-filter-")
    namespace = ctx.unique_name("sim2reallogsmfneg2")

    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    # Break exactly one thing: target a log group name that was never created.
    code, message = _client_error(
        lambda: logs.put_metric_filter(
            logGroupName=bogus_log_group,
            filterName=filter_name,
            filterPattern='"ERROR"',
            metricTransformations=[
                {"metricName": "ErrorCount", "metricNamespace": namespace, "metricValue": "1", "defaultValue": 0}
            ],
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The specified log group does not exist.", f"unexpected message: {message!r}"

    describe_code, describe_message = _client_error(
        lambda: logs.describe_metric_filters(logGroupName=bogus_log_group)
    )
    assert describe_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {describe_code}"
    assert describe_message == "The specified log group does not exist.", f"unexpected message: {describe_message!r}"

    # Effect absent: no metric filter exists under the bogus name in the real log group either.
    real_group_filters = logs.describe_metric_filters(logGroupName=log_group)["metricFilters"]
    assert real_group_filters == [], "the rejected PutMetricFilter must not have created anything"

    # Positive control: the identical call against the real log group succeeds.
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern='"ERROR"',
        metricTransformations=[
            {"metricName": "ErrorCount", "metricNamespace": namespace, "metricValue": "1", "defaultValue": 0}
        ],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name))
    listed = logs.describe_metric_filters(logGroupName=log_group)["metricFilters"]
    actual_names = [f["filterName"] for f in listed]
    assert actual_names == [filter_name], f"expected [{filter_name!r}], got {actual_names!r}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
