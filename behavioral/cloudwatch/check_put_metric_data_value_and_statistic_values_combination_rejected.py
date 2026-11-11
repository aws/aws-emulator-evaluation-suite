"""put-metric-data-value-and-statistic-values-combination-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-metric-data-value-and-statistic-values-combination-rejected"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Supplying both Value and StatisticValues on one MetricDatum is rejected; once a Value-only
    control on the same metric and timestamp is readable, its bucket holds that control alone."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-badcombo-")
    bad_metric = ctx.unique_name("BadComboMetric-")
    now = datetime.now(timezone.utc)

    err = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": bad_metric,
                    "Timestamp": now,
                    "Value": 5.0,
                    "StatisticValues": {"SampleCount": 1, "Sum": 5.0, "Minimum": 5.0, "Maximum": 5.0},
                }
            ],
        )
    )
    assert err["Code"] == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {err!r}"
    expected = "The parameters MetricData.member.1.Value and MetricData.member.1.StatisticValues are mutually exclusive and you have specified both."
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # Positive control on the same metric and timestamp: a stored rejected datum would add a
    # sample to the bucket this control lands in.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": bad_metric, "Timestamp": now, "Value": 7.0}],
    )
    datapoint = _poll_until(
        lambda: _get_single_datapoint(cw, namespace, bad_metric, now),
        lambda dp: dp is not None,
        timeout_s=120.0,
        budget_s=_budget_s(ctx, 120.0),
        interval_s=2.0,
    )
    assert datapoint is not None, "positive control metric never appeared"
    assert datapoint["SampleCount"] == 1.0 and abs(datapoint["Average"] - 7.0) < 1e-6, (
        f"the bucket must hold only the 7.0 control (a stored rejected datum adds a sample), "
        f"got {datapoint!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available
    and must not be reduced to a plain code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"real AWS rejects Value+StatisticValues on one MetricDatum, but the call SUCCEEDED "
        f"and returned {result!r}"
    )


def _get_single_datapoint(cw, namespace, metric_name, when):
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=when - timedelta(minutes=5),
        EndTime=when + timedelta(minutes=5),
        Period=60,
        Statistics=["Average", "SampleCount"],
    )
    points = resp.get("Datapoints", [])
    return points[0] if points else None


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, budget_s=None):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
