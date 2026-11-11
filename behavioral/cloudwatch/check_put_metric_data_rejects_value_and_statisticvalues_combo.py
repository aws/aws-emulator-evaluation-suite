"""put-metric-data-rejects-value-and-statisticvalues-combo."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-rejects-value-and-statisticvalues-combo"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _error(fn):
    """Return the botocore Error dict of the ClientError fn() raises; raise if it succeeds."""
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

def _poll_until(probe, predicate, *, timeout_s, interval_s, budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            if budget_s is not None and budget_s < timeout_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{timeout_s}s wait ended (last={result!r}); not graded"
                )
            return result
        time.sleep(interval_s)
        result = probe()
    return result

@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A datum with both Value and StatisticValues is rejected with InvalidParameterCombination;
    once a Value-only control on the same metric and timestamp is readable, its bucket holds that
    control alone."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    bad_metric = "Bogus"
    now = datetime.now(timezone.utc).replace(microsecond=0)

    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": bad_metric,
                    "Timestamp": now,
                    "Value": 1.0,
                    "StatisticValues": {
                        "SampleCount": 1,
                        "Sum": 1.0,
                        "Minimum": 1.0,
                        "Maximum": 1.0,
                    },
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

    # Positive control on the same metric and timestamp: a stored rejected datum would add a
    # sample to the bucket this control lands in.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": bad_metric, "Timestamp": now, "Value": 3.0}],
    )
    datapoints = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=bad_metric,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=60,
            Statistics=["SampleCount", "Sum"],
        )["Datapoints"],
        lambda dps: len(dps) > 0,
        timeout_s=120.0,
        budget_s=_budget_s(ctx, 120.0),
        interval_s=5.0,
    )
    assert datapoints, "positive control metric datum never became visible via GetMetricStatistics"
    assert len(datapoints) == 1, f"expected the control's single bucket, got {datapoints!r}"
    assert datapoints[0]["SampleCount"] == 1.0 and abs(datapoints[0]["Sum"] - 3.0) < 1e-6, (
        f"the bucket must hold only the 3.0 control (a stored rejected datum adds a sample), "
        f"got {datapoints[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
