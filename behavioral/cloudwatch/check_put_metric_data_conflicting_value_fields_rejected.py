"""put-metric-data-conflicting-value-fields-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-metric-data-conflicting-value-fields-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData rejects a MetricDatum with both Value and StatisticValues with
    InvalidParameterCombination; a Value-only datum on the same metric and timestamp is then
    readable as the metric's only sample (SampleCount 1), so the rejected datum was not stored."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/ConflictCheck-")
    metric_name = "ConflictingFieldsMetric"
    now = time.time()

    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": 5.0,
                    "StatisticValues": {
                        "SampleCount": 1.0,
                        "Sum": 5.0,
                        "Minimum": 5.0,
                        "Maximum": 5.0,
                    },
                    "Timestamp": now,
                }
            ],
        )
    )
    assert error["Code"] == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for Value+StatisticValues, got {error!r}"
    )
    assert error["Message"] == (
        "The parameters MetricData.member.1.Value and MetricData.member.1.StatisticValues are "
        "mutually exclusive and you have specified both."
    ), error["Message"]

    # Positive control: Value alone (no StatisticValues) is accepted.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 5.0, "Timestamp": now}],
    )
    datapoints = _poll_datapoints(cw, namespace, metric_name, now, timeout_s=120.0, budget_s=_budget_s(ctx, 120.0))
    assert datapoints, "valid PutMetricData call never became visible via GetMetricStatistics"
    # Ingestion is asynchronous, so the rejected datum's absence is read only once the control
    # (same metric, same timestamp) is readable: a stored rejected datum would add a sample.
    assert [(p["SampleCount"], p["Sum"]) for p in datapoints] == [(1.0, 5.0)], (
        f"rejected metric datum was persisted anyway: {datapoints!r}"
    )


def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"real AWS rejects Value+StatisticValues on one MetricDatum, but the call SUCCEEDED "
        f"and returned {result!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_datapoints(cw, namespace, metric_name, around_ts, timeout_s, interval_s=5.0, budget_s=None):
    """Poll until datapoints appear; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    while time.monotonic() < deadline:
        points = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=around_ts - 300,
            EndTime=around_ts + 300,
            Period=60,
            Statistics=["SampleCount", "Sum"],
        )["Datapoints"]
        if points:
            return points
        time.sleep(interval_s)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait for datapoints ended; not graded"
        )
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
