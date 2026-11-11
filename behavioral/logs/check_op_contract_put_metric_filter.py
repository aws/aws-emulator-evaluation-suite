"""op-contract-putMetricFilter."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-putMetricFilter"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricFilter creates a filter DescribeMetricFilters returns as configured; on a missing group
    PutMetricFilter and DescribeMetricFilters get ResourceNotFoundException, and the same Put succeeds
    once the group exists.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    filter_name = ctx.unique_name("sim2real-behav-mf-")
    logs.put_metric_filter(
        logGroupName=group_name,
        filterName=filter_name,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": "ErrorCount",
                "metricNamespace": "Sim2RealBehavioral",
                "metricValue": "1",
                "defaultValue": 0.0,
            }
        ],
    )
    ctx.on_cleanup(
        lambda: logs.delete_metric_filter(logGroupName=group_name, filterName=filter_name)
    )

    resp = logs.describe_metric_filters(logGroupName=group_name, filterNamePrefix=filter_name)
    matches = [f for f in resp["metricFilters"] if f["filterName"] == filter_name]
    assert len(matches) == 1, f"expected exactly one metric filter, got {matches}"
    mf = matches[0]
    assert mf["filterPattern"] == "ERROR", f"expected filterPattern 'ERROR', got {mf['filterPattern']!r}"
    assert mf["metricTransformations"][0]["metricName"] == "ErrorCount", (
        f"expected metricName 'ErrorCount', got {mf['metricTransformations'][0]['metricName']!r}"
    )
    assert mf["metricTransformations"][0]["metricNamespace"] == "Sim2RealBehavioral", (
        f"expected metricNamespace 'Sim2RealBehavioral', got {mf['metricTransformations'][0]['metricNamespace']!r}"
    )

    # Break exactly one thing: target a log group name that was never created.
    missing_group = ctx.unique_name("sim2real-behav-missing-lg-")
    missing_filter = ctx.unique_name("sim2real-behav-mf2-")
    put_against_missing_group = lambda: logs.put_metric_filter(
        logGroupName=missing_group,
        filterName=missing_filter,
        filterPattern="ERROR",
        metricTransformations=[
            {
                "metricName": "ErrorCount2",
                "metricNamespace": "Sim2RealBehavioral",
                "metricValue": "1",
            }
        ],
    )
    code, message = _client_error(put_against_missing_group)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The specified log group does not exist.", f"unexpected message: {message!r}"

    # Effect absent, via an independent read: the group -- and therefore anything in it -- does
    # not exist.
    describe_code, describe_message = _client_error(lambda: logs.describe_metric_filters(logGroupName=missing_group))
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading back the same nonexistent group, got {describe_code}"
    )
    assert describe_message == "The specified log group does not exist.", f"unexpected message: {describe_message!r}"

    # Restore: with the log group created, the identical PutMetricFilter call must succeed --
    # so the rejection above tracked the missing dependency, not a blanket refusal.
    logs.create_log_group(logGroupName=missing_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=missing_group))
    put_against_missing_group()
    ctx.on_cleanup(
        lambda: logs.delete_metric_filter(logGroupName=missing_group, filterName=missing_filter)
    )

    restored = logs.describe_metric_filters(logGroupName=missing_group, filterNamePrefix=missing_filter)[
        "metricFilters"
    ]
    assert [f["filterName"] for f in restored] == [missing_filter], (
        f"expected {missing_filter} visible once the log group existed, got {restored}"
    )


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
