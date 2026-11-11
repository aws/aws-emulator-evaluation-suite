"""get-metric-data-query-at-retention-boundary-returns-exact-cutoff."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-query-at-retention-boundary-returns-exact-cutoff"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData's EndTime is exclusive: a datapoint stamped exactly at EndTime is
    excluded, while an earlier datapoint inside the window is returned with its value."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-cw-cutoff-")
    metric_name = "CutoffMetric"
    dims = [{"Name": "Case", "Value": "cutoff"}]

    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    t0 = now - timedelta(minutes=2)
    t1 = now - timedelta(minutes=1)

    cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {"MetricName": metric_name, "Dimensions": dims, "Timestamp": t0, "Value": 5.0, "Unit": "Count"},
            {"MetricName": metric_name, "Dimensions": dims, "Timestamp": t1, "Value": 7.0, "Unit": "Count"},
        ],
    )

    query = [
        {
            "Id": "cutoff",
            "MetricStat": {
                "Metric": {"Namespace": ns, "MetricName": metric_name, "Dimensions": dims},
                "Period": 60,
                "Stat": "Sum",
            },
            "ReturnData": True,
        }
    ]

    deadline = time.monotonic() + 90.0
    pairs = None
    while time.monotonic() < deadline:
        resp = cw.get_metric_data(MetricDataQueries=query, StartTime=t0 - timedelta(seconds=30), EndTime=t1)
        result = resp["MetricDataResults"][0]
        if result["Timestamps"]:
            pairs = list(zip(result["Timestamps"], result["Values"]))
            break
        time.sleep(3)

    assert pairs is not None, "no datapoint observed inside the query window within the poll timeout"
    assert len(pairs) == 1, f"expected exactly one datapoint strictly before EndTime, got {pairs}"
    ts, val = pairs[0]
    assert ts == t0 and val == 5.0, f"expected (t0={t0}, 5.0) as the only in-window datapoint, got ({ts}, {val})"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
