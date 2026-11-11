"""get-log-record-from-query-result."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-log-record-from-query-result"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQuery -> GetQueryResults yields an @ptr that GetLogRecord resolves to the full event."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lr-")
    stream_name = "stream-1"
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    messages = [
        "order-created:1001",
        "order-shipped:1002",
        "order-cancelled:1003",
    ]
    events = [{"timestamp": now_ms + i * 1000, "message": m} for i, m in enumerate(messages)]
    logs.put_log_events(logGroupName=group_name, logStreamName=stream_name, logEvents=events)

    start_time_s = (now_ms // 1000) - 300
    end_time_s = (now_ms // 1000) + 300
    query_string = "fields @timestamp, @message, @ptr | sort @timestamp asc"

    def _run_query_once():
        query_id = logs.start_query(
            logGroupName=group_name,
            startTime=start_time_s,
            endTime=end_time_s,
            queryString=query_string,
        )["queryId"]
        ctx.on_cleanup(lambda qid=query_id: _best_effort_stop(logs, qid))
        return _poll_until(
            lambda: logs.get_query_results(queryId=query_id),
            lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
            timeout_s=60.0,
            interval_s=2.0,
        )

    # A just-ingested event can take a little while to become queryable via Insights. A query
    # that reaches "Complete" before indexing catches up is not a terminal failure -- polling the
    # same completed query again would just keep returning the same stale result, so re-issue a
    # fresh query each round instead until every ingested row is visible or the budget runs out.
    overall_deadline = time.monotonic() + 240.0
    result = _run_query_once()
    while time.monotonic() < overall_deadline and (
        result["status"] != "Complete" or len(result["results"]) < len(messages)
    ):
        time.sleep(2)
        result = _run_query_once()

    if result["status"] != "Complete" or len(result["results"]) < len(messages):
        raise AssertionError(
            f"Insights query never returned all {len(messages)} ingested rows within budget "
            f"(status={result['status']!r}, rows={len(result['results'])})"
        )
    rows = result["results"]

    first_row = {field["field"]: field["value"] for field in rows[0]}
    assert first_row["@message"] == messages[0], first_row
    ptr = first_row["@ptr"]
    assert ptr, "expected a non-empty @ptr pointer in query results"

    record = logs.get_log_record(logRecordPointer=ptr)["logRecord"]
    assert record["@message"] == messages[0], record
    assert "@timestamp" in record, record


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _best_effort_stop(logs, query_id):
    """Stop the query; one that is gone or has already ended needs no stop, anything else raises."""
    try:
        logs.stop_query(queryId=query_id)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "InvalidParameterException" and "Query is already ended" in error.get("Message", ""):
            return
        if error["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
