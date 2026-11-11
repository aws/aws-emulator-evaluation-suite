"""delete-metric-filter-stops-future-metric-emission."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-metric-filter-stops-future-metric-emission"
GROUP = "e2e"
SERVICES = ["logs"]
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A metric filter counts a matching event; after DeleteMetricFilter the filter is unlisted, a second delete
    is refused with the exact message and a new match adds nothing; re-creating it counts again. After the log
    group is deleted, PutLogEvents raises ResourceNotFoundException with the exact message."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    log_group = ctx.unique_name("sim2real-logs-mfdel-")
    log_stream = ctx.unique_name("stream-")
    namespace = ctx.unique_name("Sim2RealMFDel/")
    metric_name = "MarkerCount"
    filter_name = ctx.unique_name("marker-filter-")

    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _delete_group_if_present(logs, log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    def _put_filter():
        logs.put_metric_filter(
            logGroupName=log_group,
            filterName=filter_name,
            filterPattern="MARKER",
            metricTransformations=[
                {"metricName": metric_name, "metricNamespace": namespace, "metricValue": "1"}
            ],
        )

    _put_filter()

    # --- Positive control: while the filter exists, a matching event increments it.
    range_start = datetime.now(timezone.utc)
    positive_control_started = time.monotonic()
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "MARKER event before delete"}],
    )
    sum_before = _wait_for_metric_sum(cw, namespace, metric_name, [], range_start)
    if sum_before is None:
        raise AssertionError(
            "CloudWatch metric datapoint for the pre-delete matching event never landed "
            "within the run budget -- unable to establish the positive control"
        )
    assert sum_before >= 1, f"expected metric to have incremented before delete, got {sum_before}"
    # Measured on THIS wiring, in THIS run: how long real emission took to land. The post-delete
    # absence window below is calibrated off this instead of a guessed constant, so a target whose
    # ingestion is merely slow (not blocked) cannot be mistaken for one that stopped emitting.
    positive_latency_s = time.monotonic() - positive_control_started

    # --- Break: delete the filter.
    logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name)
    remaining = [
        f["filterName"]
        for page in logs.get_paginator("describe_metric_filters").paginate(
            logGroupName=log_group, filterNamePrefix=filter_name)
        for f in page.get("metricFilters", [])
    ]
    assert filter_name not in remaining, f"deleted filter {filter_name} still listed: {remaining!r}"
    refused = _expect_error(lambda: logs.delete_metric_filter(logGroupName=log_group, filterName=filter_name),
                            ("ResourceNotFoundException",))
    expected_message = "The specified metric filter does not exist."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # CloudWatch buckets custom-metric datapoints into 60s-aligned periods, so a query that starts
    # only seconds after the pre-delete event can still surface ITS datapoint (same bucket) even
    # though the metric filter that produced it is long gone. Cross into a fresh minute boundary
    # before sending the "after delete" event so the two events cannot land in the same period,
    # then compare against the established baseline instead of expecting a bare absence.
    _sleep_to_next_minute_boundary(min_sleep_s=5.0, max_sleep_s=65.0)

    # --- Effect-absent: a NEW matching event after deletion must not add to the metric.
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "MARKER event after delete"}],
    )
    # Poll the FULL range (range_start -> now) for a bounded window: if the post-delete event still
    # emits, the running total will climb past sum_before; if deletion truly stopped emission, the
    # total must stay pinned at sum_before for the whole window. The window is >=3x the positive
    # control's own measured latency (floor 60s) so a target that is merely slow to ingest -- not
    # blocked -- cannot exhaust the window before its datapoint would have landed.
    negative_window_s = max(60.0, 3.0 * positive_latency_s)
    deadline = time.monotonic() + negative_window_s
    total_final = sum_before
    while time.monotonic() < deadline:
        total_final = _metric_sum(cw, namespace, metric_name, [], range_start)
        assert total_final <= sum_before, (
            f"metric {metric_name} grew from {sum_before} to {total_final} for an event "
            "ingested AFTER its metric filter was deleted"
        )
        time.sleep(15.0)

    # --- Repair only the withheld thing: re-create the identical filter and re-prove delivery.
    _put_filter()
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "MARKER event after re-create"}],
    )
    deadline = time.monotonic() + POLL_BUDGET_S
    total_repaired = _metric_sum(cw, namespace, metric_name, [], range_start)
    while total_repaired <= total_final and time.monotonic() < deadline:
        time.sleep(15.0)
        total_repaired = _metric_sum(cw, namespace, metric_name, [], range_start)
    assert total_repaired > total_final, (
        f"metric {metric_name} stayed at {total_repaired} after the identical filter was re-created "
        f"and a matching event sent; expected it to grow past {total_final}"
    )

    # The log group is deleted and gone: unlisted, and a write to it is refused.
    logs.delete_log_group(logGroupName=log_group)
    groups = [
        g["logGroupName"]
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=log_group)
        for g in page.get("logGroups", [])
    ]
    assert log_group not in groups, f"deleted log group {log_group} still listed"
    refused = _expect_error(lambda: logs.put_log_events(
                  logGroupName=log_group, logStreamName=log_stream,
                  logEvents=[{"timestamp": int(time.time() * 1000), "message": "MARKER after group delete"}],
    ), ("ResourceNotFoundException",))
    expected_message = "The specified log group does not exist."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _delete_group_if_present(logs, name):
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _metric_sum(cw, namespace, metric_name, dimensions, start_time):
    """Single-shot: total Sum for (namespace, metric_name, dimensions) over
    [start_time, now+1min], with no polling/waiting of its own."""
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start_time - timedelta(seconds=5),
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=1),
        Period=60,
        Statistics=["Sum"],
    )
    return sum(dp["Sum"] for dp in resp.get("Datapoints", []))


def _sleep_to_next_minute_boundary(min_sleep_s=5.0, max_sleep_s=65.0):
    """Sleep until just after the next wall-clock minute rolls over (bounded),
    so a subsequent event lands in a fresh 60s CloudWatch period distinct from
    whatever period the previous event's datapoint was bucketed into."""
    now = time.time()
    seconds_into_minute = now % 60.0
    wait = (60.0 - seconds_into_minute) + 2.0
    wait = max(min_sleep_s, min(wait, max_sleep_s))
    time.sleep(wait)


def _wait_for_metric_sum(cw, namespace, metric_name, dimensions, start_time, timeout_s=POLL_BUDGET_S, interval_s=15.0):
    """Poll CloudWatch for a Sum datapoint on (namespace, metric_name, dimensions)
    covering [start_time, now]. Returns the total sum once seen, or None if it
    never lands within timeout_s (used both to await emission and to confirm its
    absence over a bounded window)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        end_time = datetime.now(timezone.utc) + timedelta(minutes=1)
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time - timedelta(seconds=5),
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
