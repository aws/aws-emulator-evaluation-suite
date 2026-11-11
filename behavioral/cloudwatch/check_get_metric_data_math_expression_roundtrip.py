"""get-metric-data-math-expression-roundtrip."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-math-expression-roundtrip"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData evaluates a math expression over two published metrics and
    returns the correctly computed sum, with StatusCode Complete."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    now = datetime.now(timezone.utc)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": "MetricA", "Timestamp": now, "Value": 10.0, "Unit": "Count"},
            {"MetricName": "MetricB", "Timestamp": now, "Value": 25.0, "Unit": "Count"},
        ],
    )

    queries = [
        {
            "Id": "m1",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": "MetricA"},
                "Period": 300,
                "Stat": "Sum",
            },
            "ReturnData": False,
        },
        {
            "Id": "m2",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": "MetricB"},
                "Period": 300,
                "Stat": "Sum",
            },
            "ReturnData": False,
        },
        {"Id": "e1", "Expression": "m1 + m2", "Label": "Total", "ReturnData": True},
    ]

    def _result():
        resp = cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
        )
        results = {r["Id"]: r for r in resp["MetricDataResults"]}
        e1 = results.get("e1")
        if e1 and e1["StatusCode"] == "Complete" and e1["Values"]:
            return e1
        return None

    result = _poll_until(_result, lambda r: r is not None, timeout_s=120, interval_s=5)
    assert result["StatusCode"] == "Complete", f"expected StatusCode Complete, got {result['StatusCode']}"
    assert result["Values"][0] == 35.0, f"expected math expression value 35.0, got {result['Values']}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for condition; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
