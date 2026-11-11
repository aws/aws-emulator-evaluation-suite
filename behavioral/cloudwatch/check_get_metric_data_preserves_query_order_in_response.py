"""get-metric-data-preserves-query-order-in-response."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-preserves-query-order-in-response"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData returns MetricDataResults in the same order the queries were submitted."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-mdq-ns-")
    # Deliberately non-alphabetical metric/query naming so a sorted response would be detectable.
    metric_names = ["ZetaMetric", "AlphaMetric", "MuMetric", "BetaMetric"]
    query_ids = ["query_zeta", "query_alpha", "query_mu", "query_beta"]
    now = datetime.now(timezone.utc).replace(microsecond=0)

    for name in metric_names:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": name, "Timestamp": now, "Value": 7.0, "Unit": "Count"}],
        )

    queries = [
        {
            "Id": qid,
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": mname},
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": True,
        }
        for qid, mname in zip(query_ids, metric_names)
    ]

    deadline = time.monotonic() + 120
    got_data = False
    last_ids: list[str] = []
    while time.monotonic() < deadline:
        resp = cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
        )
        results = resp["MetricDataResults"]
        last_ids = [r["Id"] for r in results]
        assert last_ids == query_ids, f"response order {last_ids} != submitted order {query_ids}"
        if any(r.get("Values") for r in results):
            got_data = True
            break
        time.sleep(5)

    assert got_data, f"metric data never appeared within timeout (last order observed: {last_ids})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
