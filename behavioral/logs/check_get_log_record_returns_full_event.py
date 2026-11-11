"""get-log-record-returns-full-event."""

from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "get-log-record-returns-full-event"
GROUP = "state-machine"
SERVICES = ["logs"]


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """GetLogRecord returns the full field set for a record pointed to by an Insights @ptr."""

    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-logs-record-")
    log_stream_name = ctx.unique_name("sim2real-logs-record-stream-")
    logs.create_log_group(
        logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)

    marker = f"sim2real-{uuid.uuid4().hex}"
    now_ms = int(time.time() * 1000)
    message = f"order processed marker={marker} amount=42.50"
    logs.put_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        logEvents=[{"timestamp": now_ms, "message": message}],
    )

    query_string = (
        f"fields @ptr, @message, @logStream | filter @message like /{marker}/"
    )

    def _run_query_once():
        query_id = logs.start_query(
            logGroupName=log_group_name,
            startTime=now_ms // 1000 - 300,
            endTime=now_ms // 1000 + 300,
            queryString=query_string,
        )["queryId"]
        return _poll_until(
            lambda: logs.get_query_results(queryId=query_id),
            lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
            timeout_s=60.0,
            interval_s=3.0,
        )

    # A just-ingested event can take a little while to become queryable via Insights. A query
    # that reaches "Complete" with zero matches before that indexing catches up is not a
    # terminal failure -- polling the *same* completed query again would just keep returning
    # the same empty result, so re-issue a fresh query each round instead until it matches or
    # the overall budget is exhausted.
    overall_deadline = time.monotonic() + 240.0
    result = _run_query_once()
    while time.monotonic() < overall_deadline and (
        result["status"] != "Complete" or not result["results"]
    ):
        time.sleep(2)
        result = _run_query_once()

    if result["status"] != "Complete" or not result["results"]:
        raise AssertionError(
            f"Insights query never returned the ingested record within budget "
            f"(status={result['status']})"
        )

    row = {field["field"]: field["value"] for field in result["results"][0]}
    ptr = row["@ptr"]
    assert row["@message"] == message
    assert row["@logStream"] == log_stream_name

    record = logs.get_log_record(logRecordPointer=ptr)["logRecord"]
    assert record["@message"] == message
    assert record["@logStream"] == log_stream_name
    assert record["@log"].endswith(f":{log_group_name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
