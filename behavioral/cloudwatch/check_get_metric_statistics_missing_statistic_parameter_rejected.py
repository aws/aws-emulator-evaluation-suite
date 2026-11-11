"""get-metric-statistics-missing-statistic-parameter-rejected."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-statistics-missing-statistic-parameter-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics with neither Statistics nor ExtendedStatistics is rejected with
    InvalidParameterCombination and its exact message, while the same query with Statistics
    returns the published datapoint (Average 55.0)."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-gms-ns-")
    metric_name = "SampleMetric"
    dim_value = ctx.unique_name("dim-")
    dimensions = [{"Name": "Case", "Value": dim_value}]

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    ts = now - datetime.timedelta(seconds=10)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{
            "MetricName": metric_name,
            "Dimensions": dimensions,
            "Timestamp": ts,
            "Value": 55.0,
            "Unit": "Count",
        }],
    )

    window_start = now - datetime.timedelta(minutes=2)
    window_end = now + datetime.timedelta(minutes=1)

    code, message = _error_code(lambda: cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric_name, Dimensions=dimensions,
        StartTime=window_start, EndTime=window_end, Period=60,
    ))
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
    expected = "At least one of the parameters Statistics and ExtendedStatistics must be specified."
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    good = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, Dimensions=dimensions,
            StartTime=window_start, EndTime=window_end, Period=60, Statistics=["Average"],
        )["Datapoints"],
        lambda pts: len(pts) > 0,
        timeout_s=60,
        interval_s=3,
    )
    assert any(abs(p["Average"] - 55.0) < 0.01 for p in good), (
        f"expected a datapoint with Average==55.0, got {good!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
