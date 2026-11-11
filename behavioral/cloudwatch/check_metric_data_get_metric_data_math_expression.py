"""metric-data-get-metric-data-math-expression."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-get-metric-data-math-expression"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData computes a metric-math expression (m1/m2) over two published
    metrics and returns the correct derived value with StatusCode=Complete."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavioral-")
    ts = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": "Numerator", "Timestamp": ts, "Value": 100.0}])
    cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": "Denominator", "Timestamp": ts, "Value": 25.0}])

    result = _poll_math_result(ctx, namespace, ts)
    if result is None:
        raise AssertionError(
            "metric math result never became available within timeout",
        )

    assert result["StatusCode"] == "Complete", result
    assert result["Values"], "expected at least one value for the ratio expression"
    assert abs(result["Values"][0] - 4.0) < 1e-6, f"expected ratio 100/25=4.0, got {result['Values'][0]}"


def _poll_math_result(ctx, namespace: str, ts, timeout_s: float = 120.0, interval_s: float = 5.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Numerator"}, "Period": 300, "Stat": "Sum"},
                    "ReturnData": False,
                },
                {
                    "Id": "m2",
                    "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Denominator"}, "Period": 300, "Stat": "Sum"},
                    "ReturnData": False,
                },
                {"Id": "ratio", "Expression": "m1 / m2", "Label": "ratio"},
            ],
            StartTime=ts - timedelta(minutes=5),
            EndTime=ts + timedelta(minutes=5),
        )
        ids = {result["Id"] for result in resp["MetricDataResults"]}
        assert "m1" not in ids and "m2" not in ids, (
            f"ReturnData=False on the raw queries 'm1'/'m2' should suppress them from the "
            f"response, but the response included ids {sorted(ids)!r}"
        )
        for result in resp["MetricDataResults"]:
            if result["Id"] == "ratio" and result["StatusCode"] == "Complete" and result["Values"]:
                return result
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
