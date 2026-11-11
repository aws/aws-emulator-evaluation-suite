"""put-metric-filter-matching-events-emits-datapoint."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-metric-filter-matching-events-emits-datapoint"
GROUP = "telemetry"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A log event matching a metric filter's pattern produces a real CloudWatch datapoint
    with the configured metric value, in the metric filter's own namespace."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("sim2real-logs-mf-")
    log_stream = ctx.unique_name("sim2real-stream-")
    filter_name = ctx.unique_name("sim2real-filter-")
    namespace = ctx.unique_name("sim2reallogsmf")
    metric_name = "ErrorCount"

    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern='"ERROR"',
        metricTransformations=[
            {
                "metricName": metric_name,
                "metricNamespace": namespace,
                "metricValue": "1",
                "defaultValue": 0,
            }
        ],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name))

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": now_ms, "message": "ERROR something broke"}],
    )

    start = now_ms / 1000.0
    sum_value = _poll_for_metric_sum(cw, namespace, metric_name, start, timeout_s=180.0)
    if sum_value is None:
        raise AssertionError(
            "metric datapoint did not land within 180s; real CloudWatch ingestion can lag "
            "several minutes -- inconclusive rather than a confirmed emulator gap"
        )
    assert sum_value == 1.0, f"expected Sum=1 for the single matching event, got {sum_value}"


def _poll_for_metric_sum(cw, namespace, metric_name, start_epoch_s, timeout_s):
    deadline = time.monotonic() + timeout_s
    start_time = start_epoch_s - 60
    while time.monotonic() < deadline:
        end_time = time.time() + 60
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start_time,
            EndTime=end_time,
            Period=3600,
            Statistics=["Sum"],
        )
        datapoints = resp.get("Datapoints", [])
        if datapoints:
            return sum(dp["Sum"] for dp in datapoints)
        time.sleep(2)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
