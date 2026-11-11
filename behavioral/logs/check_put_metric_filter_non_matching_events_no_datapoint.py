"""put-metric-filter-non-matching-events-no-datapoint."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-metric-filter-non-matching-events-no-datapoint"
GROUP = "telemetry"
SERVICES = ["logs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """One batch of two non-matching events and one matching event yields a metric Sum of exactly 1.0:
    the filter counts only the event its pattern matches.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("sim2real-logs-mfneg-")
    log_stream = ctx.unique_name("sim2real-stream-")
    filter_name = ctx.unique_name("sim2real-filter-")
    namespace = ctx.unique_name("sim2reallogsmfneg")
    metric_name = "ErrorCount"

    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    # NOTE: deliberately omit defaultValue -- CloudWatch Logs treats a metric
    # transformation with a defaultValue as "always emit a datapoint (0 when no
    # events match)" for every ingestion period, which would defeat this check's
    # premise (absence of any datapoint for non-matching events). Without
    # defaultValue, a datapoint is only ever published when the pattern matches.
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern='"ERROR"',
        metricTransformations=[
            {
                "metricName": metric_name,
                "metricNamespace": namespace,
                "metricValue": "1",
            }
        ],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name))

    now_ms = int(time.time() * 1000)
    # Two non-matching events and one genuinely matching ("ERROR") event, sent together --
    # the twin control that makes absence provable rather than merely unobserved.
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[
            {"timestamp": now_ms, "message": "INFO all systems nominal"},
            {"timestamp": now_ms + 1, "message": "DEBUG heartbeat ok"},
            {"timestamp": now_ms + 2, "message": "ERROR something broke"},
        ],
    )

    # Bounded poll for the positive control to land -- breaks as soon as a datapoint
    # appears, rather than waiting out a fixed wall-clock window regardless of outcome.
    deadline = time.monotonic() + 180.0
    start_time = (now_ms / 1000.0) - 60
    sum_value = None
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start_time,
            EndTime=time.time() + 60,
            Period=3600,
            Statistics=["Sum"],
        )
        points = resp.get("Datapoints", [])
        if points:
            sum_value = sum(p["Sum"] for p in points)
            break
        time.sleep(2)

    assert sum_value is not None, (
        "the positive control ('ERROR something broke', sent alongside the two non-matching "
        "events) never produced a metric datapoint within 180s -- either metric filters do not "
        "deliver on this target, or the absence below is unobserved rather than proven"
    )
    assert sum_value == 1.0, (
        f"expected Sum=1.0 -- exactly the one matching 'ERROR' event -- but CloudWatch reported "
        f"{sum_value}; a target that also counts the two non-matching events (INFO/DEBUG) fails "
        "pattern selectivity"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
