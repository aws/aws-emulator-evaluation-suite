"""put-metric-filter-dimensions-preserved-in-metric-data."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-filter-dimensions-preserved-in-metric-data"
GROUP = "telemetry"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutMetricFilter dimension is echoed verbatim by DescribeMetricFilters and attached, with
    its resolved value, to the emitted CloudWatch metric data point.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("sim2real-logs-mfdim-")
    log_stream = ctx.unique_name("stream-")
    namespace = ctx.unique_name("Sim2RealMFDim/")
    metric_name = "RequestSize"
    filter_name = "filter-with-dim"

    logs.create_log_group(logGroupName=log_group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    declared_dimensions = {"StatusCode": "$status_code"}
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern="[ip, status_code, size]",
        metricTransformations=[
            {
                "metricName": metric_name,
                "metricNamespace": namespace,
                "metricValue": "$size",
                "dimensions": declared_dimensions,
            }
        ],
    )

    described = logs.describe_metric_filters(logGroupName=log_group, filterNamePrefix=filter_name)[
        "metricFilters"
    ]
    assert len(described) == 1, f"expected exactly one metric filter named {filter_name!r}, got {described}"
    got_dimensions = described[0]["metricTransformations"][0].get("dimensions")
    assert got_dimensions == declared_dimensions, (
        f"expected dimensions {declared_dimensions} preserved verbatim, got {got_dimensions}"
    )

    start_time = datetime.now(timezone.utc)
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": now_ms, "message": "203.0.113.9 200 512"}],
    )

    dims = [{"Name": "StatusCode", "Value": "200"}]
    # Custom-metric ingestion can take several minutes.
    total = _wait_for_metric_sum(cw, namespace, metric_name, dims, start_time, timeout_s=240.0)
    if total is None:
        raise AssertionError(
            "CloudWatch metric datapoint for the dimensioned metric did not land within "
            "the poll window (real CloudWatch custom-metric ingestion can take several "
            "minutes) -- unable to verify the dimension's resolved value"
        )
    assert total >= 512, f"expected the $size-valued metric to sum to >=512, got {total}"


def _wait_for_metric_sum(cw, namespace, metric_name, dimensions, start_time, timeout_s=240.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end_time = datetime.now(timezone.utc) + timedelta(minutes=1)
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time - timedelta(minutes=1),
            EndTime=end_time,
            Period=60,
            Statistics=["Sum"],
        )
        datapoints = resp.get("Datapoints", [])
        total = sum(dp["Sum"] for dp in datapoints)
        if total > 0:
            return total
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
