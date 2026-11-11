"""get-metric-data-math-expression."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-math-expression"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData evaluates a metric-math expression over raw metric queries."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "Errors"
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 3.0, "Unit": "Count"}],
    )

    def probe():
        return cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {"Namespace": namespace, "MetricName": metric_name},
                        "Period": 300,
                        "Stat": "Sum",
                    },
                    "ReturnData": False,
                },
                {"Id": "e1", "Expression": "m1 * 2", "ReturnData": True},
            ],
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
        )

    def has_result(r):
        results = {x["Id"]: x for x in r.get("MetricDataResults", [])}
        return "e1" in results and len(results["e1"].get("Values", [])) > 0

    resp = _poll_until(probe, has_result, timeout_s=30, interval_s=2)
    results = {x["Id"]: x for x in resp["MetricDataResults"]}
    assert "m1" not in results, (
        f"ReturnData=False on the raw query 'm1' should suppress it from the response, "
        f"but the response included ids {sorted(results)!r}"
    )
    e1 = results["e1"]
    assert e1["StatusCode"] == "Complete", f"expected Complete, got {e1['StatusCode']}"
    assert e1["Values"][0] == 6.0, f"expected metric-math result 6.0, got {e1['Values']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
