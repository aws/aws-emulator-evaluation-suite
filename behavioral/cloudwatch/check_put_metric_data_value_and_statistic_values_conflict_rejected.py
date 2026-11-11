"""put-metric-data-value-and-statistic-values-conflict-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-value-and-statistic-values-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData rejects a datum that sets both Value and StatisticValues; a Value-only datum
    on the same metric and timestamp is then readable as the bucket's only sample, so the
    rejected datum was not stored."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealConflict")
    metric_name = "ConflictingDatum"
    now = time.time()
    bucket_start = int(now - (now % 60)) - 120
    ts = bucket_start + 30

    err = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Timestamp": ts,
                    "Value": 42.0,
                    "StatisticValues": {
                        "SampleCount": 1.0,
                        "Sum": 42.0,
                        "Minimum": 42.0,
                        "Maximum": 42.0,
                    },
                }
            ],
        )
    )
    assert err["Code"] == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {err!r}"
    expected = "The parameters MetricData.member.1.Value and MetricData.member.1.StatisticValues are mutually exclusive and you have specified both."
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    start_dt = datetime.datetime.fromtimestamp(bucket_start, tz=datetime.timezone.utc)
    end_dt = datetime.datetime.fromtimestamp(bucket_start + 60, tz=datetime.timezone.utc)
    # Positive control: the same datum with only Value succeeds and is queryable.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": ts, "Value": 42.0}],
    )
    datapoints = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start_dt,
            EndTime=end_dt,
            Period=60,
            Statistics=["SampleCount"],
        )["Datapoints"],
        lambda dps: len(dps) > 0,
        timeout_s=90.0,
        budget_s=_budget_s(ctx, 90.0),
        interval_s=3.0,
    )
    # Ingestion is asynchronous, so the rejected datum's absence is read only once the control
    # (same metric, same timestamp) is readable: a stored rejected datum would add a sample.
    assert datapoints and [p["SampleCount"] for p in datapoints] == [1.0], (
        f"expected one datapoint with SampleCount 1.0, got {datapoints!r}"
    )


def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"real AWS rejects Value+StatisticValues on one MetricDatum, but the call SUCCEEDED "
        f"and returned {result!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    stop = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    last = None
    while time.monotonic() < stop:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait ended (last={last!r}); not graded"
        )
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
