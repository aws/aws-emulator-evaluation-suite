"""start-query-without-log-group-selector-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-query-without-log-group-selector-rejected"
GROUP = 'insights'
SERVICES = ['logs']

_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _with_request_suffix(text, code, message):
    """`text` followed by the per-call suffix CloudWatch Logs appends to a refusal; only the
    36-character request id is read out of `message` rather than asserted as a fixed value."""
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", message or "")
    request_id = found.group(1) if found else "<no request id>"
    return (
        f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
        f"Request ID: {request_id}; Proxy: null)"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll(svc, query_id, *, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=query_id)
        if resp["status"] in _TERMINAL:
            return resp
        if time.monotonic() > deadline:
            raise AssertionError(f"query {query_id} still {resp['status']!r} after {timeout_s}s")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQuery with no logGroupName(s)/logGroupIdentifiers is refused with MalformedQueryException
    and starts no query, while naming the log group completes and finds the planted event.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-noselector-")
    stream = ctx.unique_name("stream-")
    marker = ctx.unique_name("sim2real-marker-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    now_ms = int(time.time() * 1000)
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": f"hello {marker} world"}],
    )

    now_s = now_ms // 1000
    query_string = "fields @message"
    first_token = query_string.split()[0]
    code, message = _error(
        lambda: svc.start_query(startTime=now_s - 3600, endTime=now_s + 60, queryString=query_string)
    )
    assert code == "MalformedQueryException", f"expected MalformedQueryException, got {code!r}: {message!r}"
    expected_message = _with_request_suffix(
        f"Invalid syntax while using query definition snippets: unexpected symbol found "
        f"{first_token} at line 1 and position 0",
        "MalformedQueryException",
        message,
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described = svc.describe_queries(logGroupName=group)
    assert described.get("queries", []) == [], (
        f"a rejected StartQuery call must not create a visible query, got {described.get('queries')!r}"
    )

    # Positive control: the same window and query string, naming the log group, completes
    # and finds the planted event -- the refusal above is specific to the missing selector.
    # Ingestion into the Insights index lags PutLogEvents, so a fresh query may complete with
    # zero rows before the event is indexed; retry until it appears or the budget runs out.
    deadline = time.monotonic() + 180.0
    result = None
    while True:
        query_id = svc.start_query(
            logGroupName=group, startTime=now_s - 3600, endTime=now_s + 60, queryString=query_string
        )["queryId"]
        result = _poll(svc, query_id)
        assert result["status"] == "Complete", f"positive-control query did not complete: {result['status']}"
        if len(result["results"]) == 1:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"planted event never appeared within 180s, last result={result['results']}")
        time.sleep(5.0)

    fields = {f["field"]: f["value"] for f in result["results"][0]}
    assert fields["@message"] == f"hello {marker} world", (
        f"expected message {'hello ' + marker + ' world'!r}, got {fields.get('@message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
