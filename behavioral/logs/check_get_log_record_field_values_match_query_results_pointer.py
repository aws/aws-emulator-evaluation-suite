"""get-log-record-field-values-match-query-results-pointer."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-log-record-field-values-match-query-results-pointer"
GROUP = "data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Field values GetLogRecord returns for a @ptr exactly match the inline values GetQueryResults
    returned for the same row (Logs Insights round-trip: ingest -> query -> record lookup)."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-lr-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    stream = ctx.unique_name("stream-")
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    marker = ctx.unique_name("marker").replace("-", "")
    now_ms = int(time.time() * 1000)
    events = [
        {"timestamp": now_ms + i, "message": json.dumps({"marker": marker, "seq": i, "level": "INFO"})}
        for i in range(3)
    ]
    logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)

    query_string = (
        f"fields @ptr, @message, @logStream | filter @message like /{marker}/ | sort @timestamp asc"
    )
    start_time = int(time.time()) - 900
    end_time = int(time.time()) + 900

    def _run_query_once():
        query_id = logs.start_query(
            logGroupName=group, startTime=start_time, endTime=end_time, queryString=query_string
        )["queryId"]
        resp = None
        for _ in range(30):
            resp = logs.get_query_results(queryId=query_id)
            if resp["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
            time.sleep(1)
        return resp

    results = None
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        resp = _run_query_once()
        if resp is not None and resp["status"] == "Complete" and resp.get("results"):
            results = resp["results"]
            break
        time.sleep(2)

    if not results:
        raise AssertionError(
            "CloudWatch Logs Insights query never returned matching results for the "
            "ingested events within 180s"
        )

    row = {field["field"]: field["value"] for field in results[0]}
    ptr = row["@ptr"]
    inline_message = row["@message"]
    inline_stream = row["@logStream"]

    record = logs.get_log_record(logRecordPointer=ptr)["logRecord"]
    assert record["@message"] == inline_message, "GetLogRecord @message must match inline query result"
    assert record["@logStream"] == inline_stream, "GetLogRecord @logStream must match inline query result"
    assert marker in record["@message"], (
        f"GetLogRecord @message must still contain marker {marker!r}: {record['@message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
