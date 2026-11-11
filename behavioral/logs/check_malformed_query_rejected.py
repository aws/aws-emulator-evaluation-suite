"""malformed-query-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "malformed-query-rejected"
GROUP = 'insights'
SERVICES = ['logs']


def _logs_refusal(text, code, message):
    """`text` with the suffix CloudWatch Logs appends to a refusal. Only the per-call request id is
    read from `message`, and only in its 36-character form."""
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", message or "")
    request_id = found.group(1) if found else "<no request id>"
    return (
        f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
        f"Request ID: {request_id}; Proxy: null)"
    )


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result={result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQuery refuses invalid Logs Insights syntax with MalformedQueryException and its exact message
    and creates no query, while a valid query on the same group completes with the marker event.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-malformedquery-")
    stream = ctx.unique_name("stream-")
    marker = ctx.unique_name("sim2real-marker-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    now_ms = int(time.time() * 1000)
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": f"hello {marker} world"}],
    )

    now = int(time.time())
    code, code_msg = _error_code(
        lambda: svc.start_query(
            logGroupName=group,
            startTime=now - 3600,
            endTime=now,
            queryString="this is not | valid @@ Insights >>> syntax {{{",
        )
    )
    # Only the internal Request ID at the end of the message varies; the response does not expose it.
    assert code == "MalformedQueryException", f"expected MalformedQueryException, got {code!r}"
    # The position counts from the service's rewritten query text, so it is read from the message.
    position = re.match(r"unexpected symbol found \| at line 1 and position (\d+) ", code_msg or "")
    expected = _logs_refusal(
        f"unexpected symbol found | at line 1 and position {position.group(1) if position else '<none>'}",
        "MalformedQueryException",
        code_msg,
    )
    assert code_msg == expected, f"expected message {expected!r}, got {code_msg!r}"

    described = svc.describe_queries(logGroupName=group)
    assert described.get("queries", []) == [], (
        f"a rejected StartQuery call must not create a visible query, got {described.get('queries')!r}"
    )

    # Positive control: a syntactically valid query over the same log group succeeds
    # end-to-end and finds the ingested event -- proving the rejection above is specific
    # to the malformed syntax, not a blanket StartQuery failure.
    def _run_query():
        qid = svc.start_query(
            logGroupName=group,
            startTime=now - 3600,
            endTime=now + 60,
            queryString=f"fields @message | filter @message like /{marker}/",
        )["queryId"]
        return _poll_until(
            lambda: svc.get_query_results(queryId=qid),
            lambda r: r["status"] in ("Complete", "Failed", "Cancelled", "Timeout"),
            timeout_s=60.0,
            interval_s=2.0,
        )

    result = None
    for _ in range(6):
        result = _run_query()
        assert result["status"] == "Complete", f"positive-control query did not complete: {result['status']}"
        if len(result["results"]) == 1:
            break
        time.sleep(5.0)

    assert len(result["results"]) == 1, f"expected exactly 1 matching record, got {result['results']}"
    fields = {f["field"]: f["value"] for f in result["results"][0]}
    assert marker in fields["@message"], f"marker not found in matched record: {fields}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
