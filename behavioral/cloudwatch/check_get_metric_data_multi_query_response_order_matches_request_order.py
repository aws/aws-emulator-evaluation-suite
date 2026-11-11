"""get-metric-data-multi-query-response-order-matches-request-order."""
from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-multi-query-response-order-matches-request-order"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData with several MetricDataQueries returns MetricDataResults in the
    same order as the requested query Ids (not alphabetical, not response-arrival order),
    and each result carries the value of the specific metric its own query named."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-cw-ord-")

    # Ids deliberately out of alphabetical / any natural order.
    ids = ["q_echo", "q_alpha", "q_charlie", "q_bravo", "q_delta"]
    now = datetime.now(timezone.utc).replace(microsecond=0)

    expected_values: dict[str, float] = {}
    queries = []
    for i, qid in enumerate(ids):
        metric_name = f"OrderMetric{i}"
        value = 100.0 * (i + 1)
        expected_values[qid] = value
        cw.put_metric_data(
            Namespace=ns,
            MetricData=[{
                "MetricName": metric_name,
                "Dimensions": [{"Name": "Case", "Value": qid}],
                "Timestamp": now,
                "Value": value,
                "Unit": "Count",
            }],
        )
        queries.append(
            {
                "Id": qid,
                "MetricStat": {
                    "Metric": {
                        "Namespace": ns,
                        "MetricName": metric_name,
                        "Dimensions": [{"Name": "Case", "Value": qid}],
                    },
                    "Period": 60,
                    "Stat": "Maximum",
                },
                "ReturnData": True,
            }
        )

    def _probe():
        return cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=now - timedelta(minutes=10),
            EndTime=now + timedelta(minutes=5),
        )["MetricDataResults"]

    def _has_all_data(results):
        return len(results) == len(ids) and all(r.get("Values") for r in results)

    results = _poll_until(_probe, _has_all_data, timeout_s=180.0, interval_s=5.0)

    got_ids = [r["Id"] for r in results]
    assert got_ids == ids, f"expected result order {ids}, got {got_ids}"

    for r in results:
        actual = r["Values"][0]
        expected = expected_values[r["Id"]]
        assert math.isclose(actual, expected, rel_tol=1e-6), (
            f"query {r['Id']} returned value {actual}, expected {expected}"
        )


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
