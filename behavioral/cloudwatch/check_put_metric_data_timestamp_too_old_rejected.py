"""put-metric-data-timestamp-too-old-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-timestamp-too-old-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A datum backdated 20 days (past the 2-week window) is rejected with InvalidParameterValue; a
    recent datum on the same metric is readable, and a window spanning both timestamps holds only it.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-oldts-")
    metric_name = "too-old-metric"

    too_old = datetime.now(timezone.utc) - timedelta(days=20)
    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric_name, "Timestamp": too_old, "Value": 1.0}],
        )
    )
    assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    assert error["Message"] == (
        "The parameter MetricData.member.1.Timestamp must specify a time within the past two weeks."
    ), error["Message"]

    # A recent timestamp: datapoints older than 3 hours can take up to 2 hours to become queryable.
    ok_ts = datetime.now(timezone.utc) - timedelta(minutes=1)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": ok_ts, "Value": 77.0}],
    )
    present = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[],
            StartTime=ok_ts - timedelta(minutes=2),
            EndTime=ok_ts + timedelta(minutes=2),
            Period=10,
            Statistics=["Sum"],
        ),
        lambda resp: len(resp["Datapoints"]) == 1,
        timeout_s=60.0,
        budget_s=_budget_s(ctx, 60.0),
        interval_s=3,
    )
    assert present["Datapoints"][0]["Sum"] == 77.0, (
        f"expected the restored write's ingested Sum to be 77.0, got {present['Datapoints'][0]['Sum']!r}"
    )

    # Effect absent: one window spanning the rejected and the recent timestamp holds only the
    # recent datum, so the absence is read in the query that shows the control. A StartTime 15-63
    # days old requires a period that is a multiple of 5 minutes; 1 hour keeps it under 1,440 points.
    window = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[],
            StartTime=too_old - timedelta(minutes=5),
            EndTime=ok_ts + timedelta(minutes=5),
            Period=3600,
            Statistics=["Sum", "SampleCount"],
        ),
        lambda resp: len(resp["Datapoints"]) >= 1,
        timeout_s=60.0,
        budget_s=_budget_s(ctx, 60.0),
        interval_s=3,
    )
    sums = [(p["SampleCount"], p["Sum"]) for p in window["Datapoints"]]
    assert sums == [(1.0, 77.0)], f"a datapoint exists despite the rejected write: {window['Datapoints']}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, budget_s=None):
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
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
