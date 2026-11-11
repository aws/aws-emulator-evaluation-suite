"""put-metric-data-nan-value-rejected."""
from __future__ import annotations

import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-nan-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutMetricData rejects a NaN metric Value with InvalidParameterValue; once a real-valued
    control in the same namespace is listed by ListMetrics, it is the namespace's only metric."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav/")
    bad_metric = "NanRejectTest"
    good_metric = "NanRejectControl"

    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": bad_metric, "Value": math.nan}],
        )
    )
    assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    assert error["Message"] == "The value NaN for parameter MetricData.member.1.Value is invalid.", error["Message"]

    # positive control: an identical call with a real value succeeds
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": good_metric, "Value": 1.0}],
    )

    # effect absent: the NaN-valued metric was never published. ListMetrics registration is
    # asynchronous ("allow up to 15 minutes for the metric to appear"), so the absence is read
    # from the same listing that first shows the control.
    listed = _poll_until(
        lambda: cw.list_metrics(Namespace=namespace)["Metrics"],
        lambda ms: any(m["MetricName"] == good_metric for m in ms),
        timeout_s=180.0,
        budget_s=_budget_s(ctx, 180.0),
        interval_s=5.0,
        description=f"control metric {good_metric!r} listed by ListMetrics",
    )
    names = sorted(m["MetricName"] for m in listed)
    assert names == [good_metric], f"expected only the control metric published, got {names}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if budget_s is not None and budget_s < timeout_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                    f"{timeout_s}s wait for {description} ended (last={last!r}); not graded"
                )
            raise AssertionError(f"{description} not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects a NaN Value, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
