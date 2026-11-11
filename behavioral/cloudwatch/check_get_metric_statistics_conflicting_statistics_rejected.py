"""get-metric-statistics-conflicting-statistics-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-metric-statistics-conflicting-statistics-rejected"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics rejects Period=45 with InvalidParameterValue and its exact message, while the
    same request with Period=60 returns the published 42.0 as Average and as p90, so the rejection
    is specific to the Period."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cwstat-ns-")
    metric_name = "TestMetric"

    now = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=2)
    cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 42.0}])
    start = now
    end = now + timedelta(seconds=60)

    def _get(**kwargs):
        return cw.get_metric_statistics(Namespace=namespace, MetricName=metric_name, StartTime=start, EndTime=end, **kwargs)

    code, message = _error_code(lambda: _get(Period=45, Statistics=["Average"]))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for non-multiple-of-60 Period, got {code!r}"
    expected = "The parameter Period must be a value in the set [1, 5, 10, 20, 30]."
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    # Positive control: the exact same request with a valid Period succeeds and returns the
    # published value, proving the rejection above isn't a blanket failure.
    stat_points = _poll_for_datapoints(lambda: _get(Period=60, Statistics=["Average"]))
    assert stat_points, "GetMetricStatistics with a valid Period never returned data"
    avg = stat_points[0]["Average"]
    assert avg == 42.0, f"expected the published value 42.0 back, got {avg!r}"

    ext_points = _poll_for_datapoints(lambda: _get(Period=60, ExtendedStatistics=["p90"]))
    assert ext_points, "GetMetricStatistics with only ExtendedStatistics never returned data"
    p90 = ext_points[0]["ExtendedStatistics"]["p90"]
    assert abs(p90 - 42.0) < 0.01, f"expected p90 of the single 42.0 datapoint, got {p90!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected InvalidParameterValue but the call succeeded and returned {result!r}"
    )


def _poll_for_datapoints(fn, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    datapoints = []
    while time.monotonic() < deadline:
        datapoints = fn().get("Datapoints", [])
        if datapoints:
            return datapoints
        time.sleep(interval_s)
    return datapoints


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
