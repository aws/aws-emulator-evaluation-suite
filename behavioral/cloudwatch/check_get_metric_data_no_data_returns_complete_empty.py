"""get-metric-data-no-data-returns-complete-empty."""
from __future__ import annotations

import datetime

from behavioral_harness import tags

CHECK = "get-metric-data-no-data-returns-complete-empty"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData for a metric that never received a datapoint returns StatusCode=Complete with empty Values."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealEmpty")
    metric_name = "NeverPublished"
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    start = now - datetime.timedelta(minutes=10)

    resp = cw.get_metric_data(
        MetricDataQueries=[
            {
                "Id": "q1",
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": metric_name},
                    "Period": 60,
                    "Stat": "Average",
                },
                "ReturnData": True,
            }
        ],
        StartTime=start,
        EndTime=now,
    )
    results = resp["MetricDataResults"]
    assert len(results) == 1, f"expected exactly one MetricDataResult for query id q1, got {results}"
    result = results[0]
    assert result["StatusCode"] == "Complete", (
        f"expected StatusCode=Complete for a never-published metric, got {result['StatusCode']}: {result}"
    )
    assert result["Values"] == [], f"expected no values for a never-published metric, got {result['Values']}"
    assert result["Timestamps"] == [], f"expected no timestamps for a never-published metric, got {result['Timestamps']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
