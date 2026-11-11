"""describe-metric-filters-multiple-filters-per-group-distinct."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-metric-filters-multiple-filters-per-group-distinct"
GROUP = "telemetry"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two metric filters on the same log group are each independently listed by
    DescribeMetricFilters, each emits metrics for only its own pattern, and deleting one
    leaves the other intact and still emitting."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("sim2real-logs-mfmulti-")
    log_stream = ctx.unique_name("sim2real-stream-")
    filter_a = ctx.unique_name("sim2real-filter-a-")
    filter_b = ctx.unique_name("sim2real-filter-b-")
    namespace = ctx.unique_name("sim2reallogsmfmulti")
    metric_a = "ErrorCount"
    metric_b = "WarnCount"

    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_a,
        filterPattern='"ERROR"',
        metricTransformations=[
            {"metricName": metric_a, "metricNamespace": namespace, "metricValue": "1", "defaultValue": 0}
        ],
    )
    logs.put_metric_filter(
        logGroupName=log_group,
        filterName=filter_b,
        filterPattern='"WARN"',
        metricTransformations=[
            {"metricName": metric_b, "metricNamespace": namespace, "metricValue": "1", "defaultValue": 0}
        ],
    )
    ctx.on_cleanup(lambda: _delete_filter_if_present(logs, log_group, filter_a))
    ctx.on_cleanup(lambda: _delete_filter_if_present(logs, log_group, filter_b))

    listed = logs.describe_metric_filters(logGroupName=log_group)["metricFilters"]
    names = {f["filterName"] for f in listed}
    assert names == {filter_a, filter_b}, f"expected both filters listed, got {names}"

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[
            {"timestamp": now_ms, "message": "ERROR disk failure"},
            {"timestamp": now_ms + 1, "message": "WARN latency spike"},
        ],
    )

    start_time = (now_ms / 1000.0) - 60
    sum_a = _poll_for_metric_sum(cw, namespace, metric_a, start_time, timeout_s=180.0)
    sum_b = _poll_for_metric_sum(cw, namespace, metric_b, start_time, timeout_s=60.0)
    if sum_a is None or sum_b is None:
        raise AssertionError(
            "one of the two independent metric filter datapoints did not land within the "
            "poll window; real CloudWatch ingestion can lag several minutes -- inconclusive"
        )
    assert sum_a == 1.0, f"filter A's metric should reflect exactly its own matching event, got {sum_a}"
    assert sum_b == 1.0, f"filter B's metric should reflect exactly its own matching event, got {sum_b}"

    # Delete filter A and confirm DescribeMetricFilters now reflects only filter B.
    logs.delete_metric_filter(logGroupName=log_group, filterName=filter_a)
    remaining = logs.describe_metric_filters(logGroupName=log_group)["metricFilters"]
    remaining_names = {f["filterName"] for f in remaining}
    assert remaining_names == {filter_b}, f"expected only filter B to remain, got {remaining_names}"

    # Filter B must still be LIVE, not just listed: a fresh matching event ingested after
    # A's deletion must independently increment B's metric, proving deleting a sibling
    # filter did not silently disable it too.
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "WARN second latency spike"}],
    )
    sum_b_after = _poll_for_metric_sum_above(cw, namespace, metric_b, start_time, sum_b, timeout_s=120.0)
    if sum_b_after is None:
        raise AssertionError(
            "filter B's metric never grew past its pre-delete sum after a fresh matching "
            "event was ingested post-delete; real CloudWatch ingestion can lag several "
            "minutes -- inconclusive whether deleting filter A silently disabled filter B too"
        )
    assert sum_b_after == sum_b + 1.0, (
        "filter B should still be independently emitting after filter A's deletion: "
        f"expected cumulative sum {sum_b + 1.0}, got {sum_b_after}"
    )


def _delete_filter_if_present(logs, log_group, filter_name):
    try:
        logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name)
    except logs.exceptions.ResourceNotFoundException:
        pass


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


def _poll_for_metric_sum_above(cw, namespace, metric_name, start_epoch_s, min_sum, timeout_s):
    """Like _poll_for_metric_sum, but only returns once the observed sum exceeds
    min_sum -- proves a NEW datapoint landed rather than reporting a stale sum
    already established by an earlier event in the same aggregation period."""
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
        total = sum(dp["Sum"] for dp in datapoints)
        if total > min_sum:
            return total
        time.sleep(2)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
