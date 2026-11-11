"""op-contract-delete-metric-filter."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-metric-filter"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMetricFilter: success path removes a previously created filter so it no
    longer appears in DescribeMetricFilters; error boundary is ResourceNotFoundException
    for a second delete of that same filter name, now that it no longer exists."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    filter_name = ctx.unique_name("sim2real-behav-mf-")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    logs.put_metric_filter(
        logGroupName=group_name,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": "ErrorCount",
                "metricNamespace": "Sim2RealBehavioral",
                "metricValue": "1",
            }
        ],
    )

    resp = logs.describe_metric_filters(logGroupName=group_name, filterNamePrefix=filter_name)
    assert len(resp["metricFilters"]) == 1, f"expected exactly one metric filter, got {resp['metricFilters']}"

    logs.delete_metric_filter(logGroupName=group_name, filterName=filter_name)

    resp = logs.describe_metric_filters(logGroupName=group_name, filterNamePrefix=filter_name)
    assert resp["metricFilters"] == [], "metric filter still present after delete"

    # error boundary: a second delete of the same (now-gone) filter name must fail
    error = _expect_error(
        lambda: logs.delete_metric_filter(logGroupName=group_name, filterName=filter_name)
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    expected_message = "The specified metric filter does not exist."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
