"""get-metric-data-query-result-order-matches-request-order."""
from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-query-result-order-matches-request-order"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData results preserve the Id order of the request, regardless of
    what order the server may have internally resolved/executed the queries in."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ord-ns-")
    metric_a = ctx.unique_name("sim2real-cw-ord-a-")
    metric_b = ctx.unique_name("sim2real-cw-ord-b-")
    metric_c = ctx.unique_name("sim2real-cw-ord-c-")
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": metric_a, "Timestamp": now, "Value": 101.0, "Unit": "Count"},
            {"MetricName": metric_b, "Timestamp": now, "Value": 202.0, "Unit": "Count"},
            {"MetricName": metric_c, "Timestamp": now, "Value": 303.0, "Unit": "Count"},
        ],
    )

    start_time = now - timedelta(minutes=10)
    end_time = now + timedelta(minutes=5)

    # Deliberately request in a non-alphabetical, non-creation order: c, a, b.
    queries = [
        {
            "Id": "queryC",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric_c},
                "Period": 60,
                "Stat": "Maximum",
            },
        },
        {
            "Id": "queryA",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric_a},
                "Period": 60,
                "Stat": "Maximum",
            },
        },
        {
            "Id": "queryB",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric_b},
                "Period": 60,
                "Stat": "Maximum",
            },
        },
    ]
    expected_order = ["queryC", "queryA", "queryB"]
    expected_values = {"queryC": 303.0, "queryA": 101.0, "queryB": 202.0}

    def _probe():
        return cw.get_metric_data(
            MetricDataQueries=queries, StartTime=start_time, EndTime=end_time
        )

    def _has_all_data(resp):
        results = resp.get("MetricDataResults", [])
        if len(results) != 3:
            return False
        return all(r.get("Values") for r in results)

    response = _poll_until(_probe, _has_all_data, timeout_s=240.0, interval_s=10.0)

    results = response["MetricDataResults"]
    actual_order = [r["Id"] for r in results]
    assert actual_order == expected_order, (
        f"result order {actual_order} does not match request order {expected_order}"
    )
    for result in results:
        expected_value = expected_values[result["Id"]]
        actual_value = result["Values"][0]
        assert math.isclose(actual_value, expected_value, rel_tol=1e-6), (
            f"query {result['Id']} returned value {actual_value}, expected {expected_value}"
        )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
