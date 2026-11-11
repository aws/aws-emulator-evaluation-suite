"""op-contract-describeMetricFilters."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeMetricFilters"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeMetricFilters returns the filter with its configured pattern and metric transformation,
    and a nonexistent log group gets ResourceNotFoundException and its exact message.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-dmf2-group-")
    filter_name = ctx.unique_name("sim2real-behav-dmf2-filter-")
    metric_namespace = ctx.unique_name("Sim2RealBehav")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.put_metric_filter(
        logGroupName=group_name,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": "ErrorCount",
                "metricNamespace": metric_namespace,
                "metricValue": "1",
                "defaultValue": 0.0,
            }
        ],
    )

    filters = logs.describe_metric_filters(logGroupName=group_name)["metricFilters"]
    assert len(filters) == 1, f"expected exactly one filter, got {filters}"
    mf = filters[0]
    assert mf["filterName"] == filter_name
    assert mf["filterPattern"] == "ERROR"
    transform = mf["metricTransformations"][0]
    assert transform["metricName"] == "ErrorCount"
    assert transform["metricNamespace"] == metric_namespace
    assert transform["metricValue"] == "1"

    missing_group = group_name + "-does-not-exist"
    code, msg = _error(lambda: logs.describe_metric_filters(logGroupName=missing_group))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
