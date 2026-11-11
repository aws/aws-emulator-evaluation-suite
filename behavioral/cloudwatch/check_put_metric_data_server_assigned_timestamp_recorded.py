"""put-metric-data-server-assigned-timestamp-recorded."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-server-assigned-timestamp-recorded"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A datapoint published via PutMetricData without an explicit Timestamp is ingested with
    a server-assigned timestamp close to the real publish time (not epoch-zero / 1970), as
    observed through GetMetricData."""
    cw = ctx.client("cloudwatch")
    namespace = "Sim2RealBehavioral"
    metric_name = ctx.unique_name("ServerTsProbe")
    dim_value = ctx.unique_name("dim-")

    publish_time = datetime.now(timezone.utc)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "CheckId", "Value": dim_value}],
                "Value": 42.0,
                "Unit": "Count",
            }
        ],
    )

    start = publish_time - timedelta(minutes=10)
    end = publish_time + timedelta(minutes=10)
    result = _poll_for_datapoint(ctx, cw, namespace, metric_name, dim_value, start, end)
    if result is None:
        raise AssertionError(
            "PutMetricData datapoint never landed in GetMetricData within the bounded poll "
            "window (real CloudWatch ingestion latency); would close by widening the window "
            "or re-running against a faster environment"
        )

    ts, value = result
    assert value == 42.0, f"expected the published value 42.0, GetMetricData returned {value}"
    delta_s = abs((ts.replace(tzinfo=timezone.utc) - publish_time).total_seconds())
    assert ts.year >= publish_time.year, f"server-assigned timestamp looks like epoch-zero: {ts}"
    assert delta_s < 900, f"server-assigned timestamp {ts} is not close to publish time {publish_time}"


# ===== helpers =====
def _poll_for_datapoint(ctx, cw, namespace, metric_name, dim_value, start, end, timeout_s: float = 240.0):
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while time.monotonic() < deadline:
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": metric_name,
                            "Dimensions": [{"Name": "CheckId", "Value": dim_value}],
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                }
            ],
            StartTime=start,
            EndTime=end,
        )
        results = resp.get("MetricDataResults", [])
        if results and results[0].get("Timestamps"):
            return results[0]["Timestamps"][0], results[0]["Values"][0]
        time.sleep(2)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
