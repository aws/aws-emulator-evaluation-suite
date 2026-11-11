"""put-metric-data-high-precision-float-value-preserved."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-high-precision-float-value-preserved"
GROUP = "representation"
SERVICES = ["cloudwatch"]

_VALUE = 3.14159265358979


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A metric value with many significant decimal digits is returned by GetMetricStatistics without rounding loss."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-precision-")
    metric_name = ctx.unique_name("HighPrecisionMetric-")
    now = datetime.now(timezone.utc)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": now,
                "Value": _VALUE,
                "Unit": "None",
            }
        ],
    )

    datapoint = _poll_until(
        lambda: _get_single_datapoint(cw, namespace, metric_name, now),
        lambda dp: dp is not None,
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert datapoint is not None, "high-precision datapoint never appeared via GetMetricStatistics"
    assert datapoint["SampleCount"] == 1.0, f"unexpected SampleCount: {datapoint['SampleCount']}"
    for stat in ("Average", "Sum", "Minimum", "Maximum"):
        got = datapoint[stat]
        assert abs(got - _VALUE) < 1e-9, f"{stat} lost precision: sent {_VALUE!r}, got {got!r}"


def _get_single_datapoint(cw, namespace, metric_name, when):
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=when - timedelta(seconds=120),
        EndTime=when + timedelta(seconds=120),
        Period=60,
        Statistics=["Average", "Sum", "Minimum", "Maximum", "SampleCount"],
    )
    points = resp.get("Datapoints", [])
    return points[0] if points else None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
