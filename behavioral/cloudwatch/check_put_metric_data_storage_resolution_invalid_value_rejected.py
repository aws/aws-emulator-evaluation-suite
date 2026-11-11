"""put-metric-data-storage-resolution-invalid-value-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-data-storage-resolution-invalid-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StorageResolution outside {1, 60} is rejected with InvalidParameterValue; StorageResolution=60
    succeeds and becomes visible in ListMetrics, after which the rejected metric is not listed.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/StorageResolution-")
    bad_metric = "BadResolutionMetric"
    good_metric = "GoodResolutionMetric"

    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": bad_metric, "Value": 1.0, "StorageResolution": 30}],
        )
    )
    assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    assert error["Message"] == (
        "The parameter MetricData.member.1.StorageResolution must be a value in the set [ 1, 60 ]."
    ), error["Message"]

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": good_metric, "Value": 1.0, "StorageResolution": 60}],
    )
    seen = _poll_until(
        lambda: cw.list_metrics(Namespace=namespace, MetricName=good_metric)["Metrics"],
        lambda ms: len(ms) > 0,
        timeout_s=120.0,
        budget_s=_budget_s(ctx, 120.0),
        interval_s=5.0,
        description=f"{good_metric!r} (StorageResolution=60) became visible in ListMetrics",
    )
    assert len(seen) == 1, f"expected exactly 1 metric for {good_metric!r}, got {seen!r}"

    # ListMetrics registration is asynchronous ("allow up to 15 minutes for the metric to
    # appear"), so the absence is read only once the control is listed.
    listed = cw.list_metrics(Namespace=namespace, MetricName=bad_metric)["Metrics"]
    assert listed == [], f"rejected metric {bad_metric!r} nonetheless appeared in ListMetrics: {listed!r}"


def _error(fn):
    """Return the botocore Error dict for a rejected call; raise on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    last = None
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
            raise AssertionError(f"{description} did not happen within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
