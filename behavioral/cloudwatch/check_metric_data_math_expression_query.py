"""metric-data-math-expression-query."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags

CHECK = "metric-data-math-expression-query"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData evaluates a metric-math expression over two raw metric series."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    ts = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": "MetricA", "Timestamp": ts, "Value": 10.0, "Unit": "Count"},
            {"MetricName": "MetricB", "Timestamp": ts, "Value": 5.0, "Unit": "Count"},
        ],
    )

    queries = [
        {
            "Id": "a",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": "MetricA"},
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": False,
        },
        {
            "Id": "b",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": "MetricB"},
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": False,
        },
        {"Id": "total", "Expression": "a + b", "Label": "Total"},
    ]

    result = _poll_for_expression_result(
        cw, queries=queries, start=ts - dt.timedelta(minutes=1), end=ts + dt.timedelta(minutes=2)
    )
    if result is None:
        raise AssertionError("metric-math result did not land within the ingestion poll window")

    assert result["Values"] == [15.0], f"expected metric math a+b == [15.0], got {result['Values']}"
    assert result["StatusCode"] == "Complete", (
        f"expected the fully-satisfied math expression to report StatusCode 'Complete', "
        f"got {result['StatusCode']!r}"
    )


def _poll_for_expression_result(cw, *, queries, start, end, timeout_s=180.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end)
        by_id = {r["Id"]: r for r in resp["MetricDataResults"]}
        assert "a" not in by_id and "b" not in by_id, (
            f"ReturnData=False on queries 'a'/'b' still returned them: got ids {sorted(by_id)!r}"
        )
        if by_id.get("total", {}).get("Values"):
            return by_id["total"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
