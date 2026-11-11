"""put-metric-filter-multiple-filters-independent-increments."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-filter-multiple-filters-independent-increments"
GROUP = "telemetry"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two independent metric filters on the same log group, both matching the
    same ingested event, each increment their OWN CloudWatch metric -- one
    filter's emission must not leak into or replace the other's."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("sim2real-logs-mf-")
    log_stream = ctx.unique_name("stream-")
    namespace = ctx.unique_name("Sim2RealMF/")

    logs.create_log_group(logGroupName=log_group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    metric_a = "ErrorCountA"
    metric_b = "ErrorCountB"

    logs.put_metric_filter(
        logGroupName=log_group,
        filterName="filter-a",
        filterPattern="ERROR",
        metricTransformations=[
            {"metricName": metric_a, "metricNamespace": namespace, "metricValue": "1"}
        ],
    )
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName="filter-b",
        filterPattern="ERROR",
        metricTransformations=[
            {"metricName": metric_b, "metricNamespace": namespace, "metricValue": "1"}
        ],
    )

    described = logs.describe_metric_filters(logGroupName=log_group)["metricFilters"]
    names = {f["filterName"] for f in described}
    assert names == {"filter-a", "filter-b"}, f"expected both filters, got {names}"

    start_time = datetime.now(timezone.utc)
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": now_ms, "message": "ERROR something broke"}],
    )

    sum_a, sum_b = _wait_for_both_metric_sums(
        cw, namespace, metric_a, metric_b, start_time, timeout_s=240.0
    )

    if sum_a is None or sum_b is None:
        raise AssertionError(
            "CloudWatch metric datapoint for one or both metric filters did not land "
            "within the poll window (real CloudWatch custom-metric ingestion can take "
            "several minutes) -- unable to verify independent increments "
            f"(sum_a={sum_a}, sum_b={sum_b})"
        )

    assert sum_a == 1, f"expected metric {metric_a} to increment by exactly 1, got sum={sum_a}"
    assert sum_b == 1, f"expected metric {metric_b} to increment by exactly 1, got sum={sum_b}"


def _wait_for_both_metric_sums(cw, namespace, metric_name_a, metric_name_b, start_time, timeout_s=240.0, interval_s=15.0):
    """Poll CloudWatch once per interval for Sum datapoints on BOTH metrics under
    (namespace, metric_name), covering [start_time, now], sharing a single deadline
    (both metrics are emitted from the same PutLogEvents call, so they land together;
    waiting on them sequentially would double the worst-case latency against the
    check's overall body budget). Returns (sum_a, sum_b), either side None if it never
    landed within timeout_s."""
    deadline = time.monotonic() + timeout_s
    sum_a = None
    sum_b = None
    while time.monotonic() < deadline:
        end_time = datetime.now(timezone.utc) + timedelta(minutes=1)
        if sum_a is None:
            sum_a = _metric_sum(cw, namespace, metric_name_a, start_time, end_time)
        if sum_b is None:
            sum_b = _metric_sum(cw, namespace, metric_name_b, start_time, end_time)
        if sum_a is not None and sum_b is not None:
            return sum_a, sum_b
        time.sleep(interval_s)
    return sum_a, sum_b


def _metric_sum(cw, namespace, metric_name, start_time, end_time):
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=[],
        StartTime=start_time - timedelta(minutes=1),
        EndTime=end_time,
        Period=60,
        Statistics=["Sum"],
    )
    datapoints = resp.get("Datapoints", [])
    total = sum(dp["Sum"] for dp in datapoints)
    return total if total > 0 else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
