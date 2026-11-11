"""start-query-end-time-before-start-time-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-query-end-time-before-start-time-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQuery rejects a request whose endTime precedes its startTime as a malformed-input
    validation error (InvalidParameterException), no query is scheduled, while a query with a
    valid time window over real log data succeeds end-to-end (positive control)."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-logs-query-")
    stream_name = ctx.unique_name("stream-")
    marker = ctx.unique_name("sim2real-marker-")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms, "message": f"hello {marker} world"}],
    )

    now_s = int(time.time())
    # endTime deliberately set before startTime -- malformed time-range input.
    code, msg = _error_code(
        lambda: logs.start_query(
            logGroupName=group_name,
            startTime=now_s,
            endTime=now_s - 3600,
            queryString="fields @message",
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r} {msg!r}"
    expected_msg = (
        "End time cannot be less than Start time (Service: AWSLogs; Status Code: 400; "
        "Error Code: InvalidParameterException; Request ID: <id>; Proxy: null)"
    )
    assert msg == expected_msg, f"unexpected message: {msg!r}"

    # Effect absent: no queries were scheduled for this log group as a result of the rejected call.
    described = logs.describe_queries(logGroupName=group_name)
    assert described["queries"] == [], f"expected no queries scheduled, found {described['queries']}"

    # Positive control: a valid window over the ingested event finds it end-to-end. Logs Insights
    # indexing can lag PutLogEvents, so the whole query is re-run until it finds the event.
    def _run_query():
        qid = logs.start_query(
            logGroupName=group_name,
            startTime=now_s - 3600,
            endTime=now_s + 60,
            queryString=f'fields @message | filter @message like /{marker}/',
        )["queryId"]
        return _poll_until(
            lambda: logs.get_query_results(queryId=qid),
            lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
            timeout_s=60.0,
            interval_s=2.0,
        )

    timeout_s = 30.0
    left = ctx.time_left()
    if left is not None:
        timeout_s = max(1.0, min(timeout_s, left - 10.0))
    deadline = time.monotonic() + timeout_s
    while True:
        result = _run_query()
        assert result["status"] == "Complete", f"query did not complete: {result['status']}"
        if len(result["results"]) == 1 or time.monotonic() >= deadline:
            break
        time.sleep(2.0)

    assert len(result["results"]) == 1, f"expected exactly 1 matching record, got {result['results']}"
    fields = {f["field"]: f["value"] for f in result["results"][0]}
    assert marker in fields["@message"], f"marker not found in matched record: {fields}"


_REQUEST_ID = re.compile(r"Request ID: [0-9a-f-]+;")


def _mask_request_id(message: str) -> str:
    """AWS appends a per-request backend Request ID to every Logs refusal; mask it."""
    return _REQUEST_ID.sub("Request ID: <id>;", message)


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), _mask_request_id(err.get("Message", ""))
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
