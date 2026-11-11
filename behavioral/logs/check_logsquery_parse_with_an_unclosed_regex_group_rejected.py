"""logsquery-parse-with-an-unclosed-regex-group-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logsquery-parse-with-an-unclosed-regex-group-rejected"
GROUP = 'insights-query'
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


def _now_ms() -> int:
    return int(time.time() * 1000)


def _row_map(row):
    return {f["field"]: f["value"] for f in row}


def _error_code(fn):
    """The AWS (code, message) fn() raised. An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded, returning {result!r}")


def _all_queries(svc, group):
    """Every query DescribeQueries knows about for this log group, across all pages."""
    out, token = [], None
    while True:
        kw = {"logGroupName": group}
        if token:
            kw["nextToken"] = token
        page = svc.describe_queries(**kw)
        out.extend(page.get("queries", []))
        token = page.get("nextToken")
        if not token:
            return out


def _run_query(svc, group, query, start_s, end_s, *, timeout_s=60):
    """One start+poll cycle, polled to a terminal status. Never asserts how long it took."""
    qid = svc.start_query(
        logGroupNames=[group], startTime=start_s, endTime=end_s, queryString=query
    )["queryId"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = svc.get_query_results(queryId=qid)
        if last["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            assert last["status"] == "Complete", (
                f"query {query!r} ended in status {last['status']!r}: {last!r}"
            )
            return last
        time.sleep(1.5)
    raise AssertionError(f"query {qid} never reached a terminal status in {timeout_s}s: {last!r}")


def _await_rows(svc, group, query, start_s, end_s, *, expect, timeout_s=150):
    """Retry the whole start+poll cycle until the ingested events are visible to the query
    engine. Ingestion into a brand-new log group is eventually consistent, so this polls for
    the value ARRIVING and never asserts how long ingestion took."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _run_query(svc, group, query, start_s, end_s)
        if len(last.get("results", [])) == expect:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"query {query!r} never returned {expect} rows within {timeout_s}s; last={last!r}"
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A ``parse`` regex with an unclosed capture group is rejected at StartQuery with
    MalformedQueryException and creates no query; the same pipeline with the group closed
    extracts the seeded values, so the rejection is attributable to the regex alone."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-lqbadregex-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    marker = ctx.unique_name("mk")

    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    latencies = ["100", "200", "300"]
    base_ms = _now_ms()
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base_ms - (len(latencies) - i) * 1000,
             "message": f"REQ {marker} lat={lat}ms"}
            for i, lat in enumerate(latencies)
        ],
    )

    now_s = base_ms // 1000
    broken = f"filter @message like /{marker}/ | parse @message /lat=(?<lat>\\d+/ | sort lat desc"
    closed = f"filter @message like /{marker}/ | parse @message /lat=(?<lat>\\d+)/ | sort lat desc"

    code, code_msg = _error_code(
        lambda: svc.start_query(
            logGroupNames=[group], startTime=now_s - 600, endTime=now_s + 120, queryString=broken
        )
    )
    # Only the internal Request ID at the end of the message varies; the response does not expose it.
    assert code == "MalformedQueryException", (
        f"a parse regex with an unclosed capture group must be rejected with "
        f"MalformedQueryException, got {code!r}"
    )
    expected = _logs_refusal(
        "Compile Error - Invalid regular expression in query: 'lat=(?<capture000>(?s)\\d+' \u2014 "
        "Unclosed group near index 25\nlat=(?<capture000>(?s)\\d+",
        "MalformedQueryException",
        code_msg,
    )
    assert code_msg == expected, (
        f"expected unclosed-group message {expected!r}, got {code_msg!r}"
    )

    # Effect-absent: the rejected call left no query behind, so it cannot surface later as a
    # Failed query or an empty Complete one.
    queries = _all_queries(svc, group)
    assert queries == [], (
        f"a rejected StartQuery must not create a query on the log group, got {queries!r}"
    )

    # Positive control: close the group and the same pipeline extracts the seeded latencies.
    ok = _await_rows(svc, group, closed, now_s - 600, now_s + 120, expect=len(latencies))
    got = [_row_map(r).get("lat") for r in ok["results"]]
    assert got == sorted(latencies, key=int, reverse=True), (
        f"the control query must extract the seeded latencies in descending order, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
