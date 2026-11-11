"""logs-insights-semantics-semantic-error-rejected-at-start."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-insights-semantics-semantic-error-rejected-at-start"
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
    raise AssertionError(f"StartQuery accepted a query real AWS refuses: {kwargs.get('queryString')!r} -> {resp!r}")


def _described_strings(svc, group):
    out = []
    for page in svc.get_paginator("describe_queries").paginate(logGroupName=group):
        out += [q.get("queryString", "") for q in page["queries"]]
    return out


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQuery refuses an unknown aggregate function and a `fields` that re-declares a parsed field
    with MalformedQueryException, the exact message and a span covering the clause, and starts no query;
    the corrected queries return the expected rows.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-semantic-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    now_ms = int(time.time() * 1000)
    ms_vals = [10, 20, 60]
    svc.put_log_events(logGroupName=group, logStreamName="s", logEvents=[
        {"timestamp": now_ms - 60_000 + i * 1000, "message": json.dumps({"ms": v, "tag": f"t{v}"})}
        for i, v in enumerate(ms_vals)])
    start_s, end_s = now_ms // 1000 - 600, now_ms // 1000 + 60

    bad_fn_clause = "bogusfn(ms)"
    bad_fn = f"fields ms | stats {bad_fn_clause} as z"
    code, msg = _start_error(svc, logGroupNames=[group], startTime=start_s, endTime=end_s, queryString=bad_fn)
    # Only the internal Request ID at the end of the message varies; the response does not expose it.
    assert code == "MalformedQueryException", f"unknown function: expected MalformedQueryException, got {code!r} {msg!r}"
    m1 = re.match(r"Unrecognized function name: bogusfn \(\[(\d+),(\d+)\]\)", msg)
    assert m1, f"unknown function: message must name 'bogusfn' with a span, got {msg!r}"
    s1, e1 = int(m1.group(1)), int(m1.group(2))
    expected = _logs_refusal(
        f"Unrecognized function name: bogusfn ([{s1},{e1}])", "MalformedQueryException", msg
    )
    assert msg == expected, f"unknown function: expected message {expected!r}, got {msg!r}"
    assert e1 - s1 == len(bad_fn_clause) - 1, f"span [{s1},{e1}] must cover {bad_fn_clause!r} exactly"

    redef_clause = "fields tg"
    redef = f"parse @message '\"tag\":\"*\"' as tg | {redef_clause}"
    code, msg = _start_error(svc, logGroupNames=[group], startTime=start_s, endTime=end_s, queryString=redef)
    # Only the internal Request ID at the end of the message varies; the response does not expose it.
    assert code == "MalformedQueryException", f"field redefinition: expected MalformedQueryException, got {code!r} {msg!r}"
    m2 = re.match(r"Ephemeral field is already defined: tg \(\[(\d+),(\d+)\]\)", msg)
    assert m2, f"field redefinition: message must name field 'tg' with a span, got {msg!r}"
    s2, e2 = int(m2.group(1)), int(m2.group(2))
    expected = _logs_refusal(
        f"Ephemeral field is already defined: tg ([{s2},{e2}])", "MalformedQueryException", msg
    )
    assert msg == expected, f"field redefinition: expected message {expected!r}, got {msg!r}"
    assert e2 - s2 == len(redef_clause) - 1, f"span [{s2},{e2}] must cover {redef_clause!r} exactly"

    assert s2 - s1 == redef.index(redef_clause) - bad_fn.index(bad_fn_clause), (
        f"spans must be offsets into the query text: {s1} vs {s2} for clauses at "
        f"{bad_fn.index(bad_fn_clause)} and {redef.index(redef_clause)}"
    )

    phantom = [s for s in _described_strings(svc, group) if "bogusfn" in s or "as tg" in s]
    assert not phantom, f"a refused StartQuery left a visible query behind: {phantom!r}"

    # Positive controls on the same data.
    ok = _query_until(svc, [group], start_s, end_s, "fields ms | stats sum(ms) as z",
                      lambda r: _rows(r) == [{"z": str(sum(ms_vals))}], what="real aggregate control")
    assert ok["status"] == "Complete", ok["status"]
    ok = _run_query(svc, [group], start_s, end_s,
                    "parse @message /\"tag\": \"(?<tg>[^\"]+)\"/ | sort tg asc | display tg")
    assert _rows(ok) == [{"tg": f"t{v}"} for v in sorted(ms_vals)], f"parse control rows {_rows(ok)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
