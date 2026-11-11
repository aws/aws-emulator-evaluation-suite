"""put-metric-data-dimension-value-control-character-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-metric-data-dimension-value-control-character-rejected"
GROUP = "representation"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A dimension value containing an ASCII control character is rejected; once a clean datum in
    the same namespace and window is readable via GetMetricStatistics and ListMetrics, the
    rejected metric is absent from both."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ctrlchar-")
    bad_metric = ctx.unique_name("BadDimMetric-")
    good_metric = ctx.unique_name("GoodDimMetric-")
    now = datetime.now(timezone.utc)

    error = _error(
        lambda: cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": bad_metric,
                    "Dimensions": [{"Name": "Host", "Value": "bad\x07value"}],
                    "Timestamp": now,
                    "Value": 1.0,
                }
            ],
        )
    )
    assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error!r}"
    # AWS reports a control character under the same non-ASCII wording.
    assert error["Message"] == (
        "The value for parameter MetricData.member.1.Dimensions.member.1.Value contains "
        "non-ASCII characters."
    ), error["Message"]

    # Positive control: a clean dimension value on the same namespace succeeds and lands.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": good_metric,
                "Dimensions": [{"Name": "Host", "Value": "clean-value"}],
                "Timestamp": now,
                "Value": 7.0,
            }
        ],
    )
    datapoint = _poll_until(
        lambda: _get_single_datapoint(cw, namespace, good_metric, now, [{"Name": "Host", "Value": "clean-value"}]),
        lambda dp: dp is not None,
        timeout_s=180.0,
        budget_s=_budget_s(ctx, 180.0),
        interval_s=10.0,
    )
    assert datapoint is not None, "positive control metric never appeared"
    assert abs(datapoint["Average"] - 7.0) < 1e-6, f"expected Average 7.0, got {datapoint['Average']!r}"

    # Effect absent: the rejected datum was never stored under that metric name. Ingestion is
    # asynchronous, so each absence read follows the control becoming readable through that API.
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=bad_metric,
        StartTime=now - timedelta(minutes=5),
        EndTime=now + timedelta(minutes=5),
        Period=60,
        Statistics=["Average"],
    )
    assert resp["Datapoints"] == [], f"rejected metric datum was persisted anyway: {resp['Datapoints']!r}"
    # ListMetrics: "After you create a metric, allow up to 15 minutes for the metric to appear."
    listed = _poll_until(
        lambda: cw.list_metrics(Namespace=namespace, MetricName=good_metric)["Metrics"],
        lambda ms: len(ms) > 0,
        timeout_s=180.0,
        budget_s=_budget_s(ctx, 180.0),
        interval_s=10.0,
    )
    assert listed, f"positive control metric {good_metric!r} never appeared in ListMetrics"
    list_resp = cw.list_metrics(Namespace=namespace, MetricName=bad_metric)
    assert list_resp["Metrics"] == [], f"rejected metric was registered in ListMetrics anyway: {list_resp['Metrics']!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _get_single_datapoint(cw, namespace, metric_name, when, dimensions=None):
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions or [],
        StartTime=when - timedelta(minutes=5),
        EndTime=when + timedelta(minutes=5),
        Period=60,
        Statistics=["Average"],
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
