"""logs-insights-semantics-unknown-log-group-rejected-at-start."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-insights-semantics-unknown-log-group-rejected-at-start"
GROUP = 'insights'
SERVICES = ['logs']


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


def _logs_refusal(text, code, message):
    """`text` with the suffix CloudWatch Logs appends to a refusal. Only the per-call request id is
    read from `message`, and only in its 36-character form."""
    found = re.search(r"; Request ID: ([0-9a-f-]{36}); Proxy: null\)$", message or "")
    request_id = found.group(1) if found else "<no request id>"
    return (
        f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
        f"Request ID: {request_id}; Proxy: null)"
    )


def _run_query(svc, groups, start_s, end_s, query, *, timeout_s=120, interval_s=1.0):
    qid = svc.start_query(
        logGroupNames=groups, startTime=start_s, endTime=end_s, queryString=query
    )["queryId"]
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        if resp["status"] in _TERMINAL:
            resp["queryId"] = qid
            return resp
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} ({query!r}) still {resp['status']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _rows(resp, *, drop=("@ptr",)):
    return [{f["field"]: f["value"] for f in row if f["field"] not in drop} for row in resp["results"]]


def _query_until(svc, groups, start_s, end_s, query, predicate, *, what, budget_s=180):
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        resp = _run_query(svc, groups, start_s, end_s, query)
        if resp["status"] == "Complete" and predicate(resp):
            return resp
        last = (resp["status"], _rows(resp, drop=()), resp.get("statistics"))
        if time.monotonic() > deadline:
            raise AssertionError(f"{what}: {query!r} never satisfied the expectation in {budget_s}s; last={last!r}")
        time.sleep(3)


def _start_error(svc, **kwargs):
    """The error StartQuery raised. A success is itself the finding, so it raises (after
    stopping the phantom query) rather than returning a sentinel that looks like a code."""
    try:
        resp = svc.start_query(**kwargs)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    try:
        svc.stop_query(queryId=resp["queryId"])
    except ClientError:
        pass
    raise AssertionError(f"StartQuery accepted a query real AWS refuses: {kwargs!r} -> {resp!r}")


def _described_strings(svc, group):
    out = []
    for page in svc.get_paginator("describe_queries").paginate(logGroupName=group):
        out += [q.get("queryString", "") for q in page["queries"]]
    return out


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """One nonexistent group among real ones refuses StartQuery with ResourceNotFoundException and a
    message naming only that group, and no partial query runs; the real group alone returns its event.
    """
    svc = ctx.client("logs")
    real = ctx.unique_name("sim2real-lisem-realgrp-")
    missing = ctx.unique_name("sim2real-lisem-nosuchgrp-")  # never created
    svc.create_log_group(logGroupName=real)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=real))
    marker = ctx.unique_name("mk")
    svc.create_log_stream(logGroupName=real, logStreamName="s")
    now_ms = int(time.time() * 1000)
    svc.put_log_events(logGroupName=real, logStreamName="s",
                       logEvents=[{"timestamp": now_ms - 60_000, "message": f"event {marker}"}])
    start_s, end_s = now_ms // 1000 - 600, now_ms // 1000 + 60
    query = f"fields @message | filter @message like '{marker}'"

    code, msg = _start_error(svc, logGroupNames=[real, missing], startTime=start_s, endTime=end_s,
                             queryString=query)
    # Only the internal Request ID at the end of the message varies; the response does not expose it.
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert f"Log group '{missing}' does not exist" in msg, f"message must name the missing group {missing!r}: {msg!r}"
    assert f"'{real}'" not in msg, f"message must not blame the group that exists: {msg!r}"
    expected = _logs_refusal(
        f"Log group '{missing}' does not exist for account ID '{ctx.account}'",
        "ResourceNotFoundException",
        msg,
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    phantom = [s for s in _described_strings(svc, real) if marker in s]
    assert not phantom, f"a refused StartQuery still ran over the real group: {phantom!r}"

    ok = _query_until(svc, [real], start_s, end_s, query, lambda r: len(r["results"]) == 1,
                      what="positive control over the real group")
    assert _rows(ok) == [{"@message": f"event {marker}"}], f"control rows {_rows(ok)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
