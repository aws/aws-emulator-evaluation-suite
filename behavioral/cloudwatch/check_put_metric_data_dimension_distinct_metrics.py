"""put-metric-data-dimension-distinct-metrics."""
from __future__ import annotations

import datetime as dt
import time

from behavioral_harness import tags

CHECK = "put-metric-data-dimension-distinct-metrics"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two datapoints for the same metric name but different dimension values are distinct series."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    metric_name = "DimensionedMetric"
    ts = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "Env", "Value": "prod"}],
                "Timestamp": ts,
                "Value": 100.0,
            },
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "Env", "Value": "dev"}],
                "Timestamp": ts,
                "Value": 1.0,
            },
        ],
    )

    prod_sum = _poll_for_sum(cw, namespace, metric_name, [{"Name": "Env", "Value": "prod"}], ts)
    if prod_sum is None:
        raise AssertionError("dimensioned metric did not land within the ingestion poll window")
    dev_sum = _poll_for_sum(cw, namespace, metric_name, [{"Name": "Env", "Value": "dev"}], ts, timeout_s=30.0)

    assert prod_sum == 100.0, f"prod series Sum should be 100.0, got {prod_sum}"
    assert dev_sum == 1.0, f"dev series Sum should be 1.0 (not conflated with prod), got {dev_sum}"


def _poll_for_sum(cw, namespace, metric_name, dimensions, ts, *, timeout_s=180.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=ts - dt.timedelta(minutes=1),
            EndTime=ts + dt.timedelta(minutes=2),
            Period=60,
            Statistics=["Sum"],
        )
        if resp["Datapoints"]:
            return resp["Datapoints"][0]["Sum"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
