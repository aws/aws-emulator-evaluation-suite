"""put-metric-data-timestamp-too-far-past-rejected."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-timestamp-too-far-past-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData rejects a datapoint timestamped more than two weeks back; a current-timestamp
    datapoint is readable, and once ListMetrics lists it, it is the namespace's only metric."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealPast-")
    rejected_metric = "RejectedPastTimestamp"
    accepted_metric = "AcceptedCurrentTimestamp"
    now = dt.datetime.now(dt.timezone.utc)

    too_far_past = now - dt.timedelta(days=20)  # AWS allows at most 2 weeks in the past
    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {"MetricName": rejected_metric, "Timestamp": too_far_past, "Value": 1.0, "Unit": "Count"}
            ],
        )
    )
    assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    assert error["Message"] == (
        "The parameter MetricData.member.1.Timestamp must specify a time within the past two weeks."
    ), error["Message"]

    # Positive control: same call shape, valid (current) timestamp, succeeds -- and the
    # datapoint is independently readable back, not just accepted at the API boundary.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": accepted_metric, "Timestamp": now, "Value": 42.0, "Unit": "Count"}],
    )
    present = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=accepted_metric,
            Dimensions=[],
            StartTime=now - dt.timedelta(minutes=2),
            EndTime=now + dt.timedelta(minutes=2),
            Period=10,
            Statistics=["Sum"],
        ),
        lambda resp: len(resp["Datapoints"]) == 1,
        timeout_s=60.0,
        budget_s=_budget_s(ctx, 60.0),
        interval_s=3,
    )
    assert present["Datapoints"][0]["Sum"] == 42.0, f"unexpected datapoint: {present['Datapoints']}"

    # Effect absent: the rejected datapoint's metric was never registered in the namespace.
    # ListMetrics registration is asynchronous ("allow up to 15 minutes for the metric to
    # appear"), so the absence is read from the same listing that first shows the control.
    listing = _poll_until(
        lambda: cw.list_metrics(Namespace=namespace)["Metrics"],
        lambda ms: any(m["MetricName"] == accepted_metric for m in ms),
        timeout_s=180.0,
        budget_s=_budget_s(ctx, 180.0),
        interval_s=5.0,
    )
    names = sorted(m["MetricName"] for m in listing)
    assert names == [accepted_metric], f"rejected datapoint's metric appeared: {names}"


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
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this timestamp, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
