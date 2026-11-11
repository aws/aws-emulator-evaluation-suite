"""put-metric-data-timestamp-window-validity."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-timestamp-window-validity"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']


_TOO_OLD = "The parameter MetricData.member.1.Timestamp must specify a time within the past two weeks."
_TOO_FUTURE = (
    "The parameter MetricData.member.1.Timestamp must specify a time no more than two hours "
    "in the future."
)


def _err(fn):
    """Call fn(); return the botocore Error dict of the ClientError it must raise.

    An unexpected SUCCESS raises rather than returning a falsy sentinel.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this timestamp, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData accepts timestamps up to 2 weeks past and 2 hours ahead, rejects others.

    Rejections are InvalidParameterValue with the exact message; once a current-timestamp control
    is listed by ListMetrics, no rejected metric is listed in the namespace.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    now = datetime.now(timezone.utc).replace(microsecond=0)

    # Comfortably inside both boundaries: accepted (no ClientError at all). Acceptance is
    # asserted at the API boundary: a backdated/future-dated datapoint has its own indexing lag
    # in GetMetricStatistics.
    past_ok = now - timedelta(days=10)
    future_ok = now + timedelta(hours=1)
    # A ClientError here fails the check: real AWS accepts this timestamp.
    cw.put_metric_data(
        Namespace=namespace, MetricData=[{"MetricName": "PastOk", "Timestamp": past_ok, "Value": 1.0}]
    )

    # A ClientError here fails the check: real AWS accepts this timestamp.
    cw.put_metric_data(
        Namespace=namespace, MetricData=[{"MetricName": "FutureOk", "Timestamp": future_ok, "Value": 2.0}]
    )

    # Outside the past boundary (> 2 weeks old): must be rejected.
    too_old = now - timedelta(days=20)
    code_old = _err(
        lambda: cw.put_metric_data(
            Namespace=namespace, MetricData=[{"MetricName": "TooOld", "Timestamp": too_old, "Value": 3.0}]
        )
    )
    assert code_old.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a >2-week-old timestamp, got {code_old!r}"
    )
    assert code_old.get("Message") == _TOO_OLD, code_old.get("Message")

    # Outside the future boundary (> 2 hours ahead): must be rejected.
    too_future = now + timedelta(hours=3)
    code_future = _err(
        lambda: cw.put_metric_data(
            Namespace=namespace, MetricData=[{"MetricName": "TooFuture", "Timestamp": too_future, "Value": 4.0}]
        )
    )
    assert code_future.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a >2h-future timestamp, got {code_future!r}"
    )
    assert code_future.get("Message") == _TOO_FUTURE, code_future.get("Message")

    # A boundary just inside the window (13 days, 23 hours ago) is still accepted...
    just_inside = now - timedelta(days=13, hours=23)
    # A ClientError here fails the check: real AWS accepts this timestamp.
    cw.put_metric_data(
        Namespace=namespace, MetricData=[{"MetricName": "JustInside", "Timestamp": just_inside, "Value": 5.0}]
    )

    # ...but a few hours further back (just outside 2 weeks) is rejected --
    # confirms the boundary is a real cutoff, not just "very old = rejected".
    just_outside = now - timedelta(days=14, hours=1)
    code_outside = _err(
        lambda: cw.put_metric_data(
            Namespace=namespace, MetricData=[{"MetricName": "JustOutside", "Timestamp": just_outside, "Value": 6.0}]
        )
    )
    assert code_outside.get("Code") == "InvalidParameterValue", (
        f"expected InvalidParameterValue for a just-past-2-weeks timestamp, got {code_outside!r}"
    )
    assert code_outside.get("Message") == _TOO_OLD, code_outside.get("Message")

    # Effect absent, via an independent operation: no rejected datapoint's metric was registered.
    # ListMetrics registration is asynchronous ("allow up to 15 minutes for the metric to
    # appear"), so the absence is read from the same listing that first shows a current control.
    cw.put_metric_data(
        Namespace=namespace, MetricData=[{"MetricName": "Control", "Timestamp": now, "Value": 7.0}]
    )
    timeout_s = 180.0
    left = ctx.time_left()
    budget_s = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    start = time.monotonic()
    stop = start + min(timeout_s, budget_s)
    while True:
        names = {m["MetricName"] for m in cw.list_metrics(Namespace=namespace)["Metrics"]}
        if "Control" in names:
            break
        if time.monotonic() >= stop:
            if budget_s < timeout_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {timeout_s}s wait for the control metric to be listed ended; not graded"
                )
            raise AssertionError(
                f"control metric not listed by ListMetrics within {timeout_s}s; listed {sorted(names)}"
            )
        time.sleep(5.0)
    rejected = names & {"TooOld", "TooFuture", "JustOutside"}
    assert rejected == set(), f"rejected datapoints' metrics appeared: {sorted(rejected)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
