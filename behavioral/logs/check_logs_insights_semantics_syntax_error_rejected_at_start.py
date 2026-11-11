"""logs-insights-semantics-syntax-error-rejected-at-start."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-insights-semantics-syntax-error-rejected-at-start"
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
    """The (code, message) StartQuery raised; a success stops the query and raises."""
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
    """StartQuery refuses an unknown command and a dangling sort with MalformedQueryException naming
    the token and a position that tracks it; no query is left behind, and the valid prefix runs.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-syntax-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    marker = ctx.unique_name("mk")
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    now_ms = int(time.time() * 1000)
    svc.put_log_events(logGroupName=group, logStreamName="s",
                       logEvents=[{"timestamp": now_ms - 60_000, "message": f"hello {marker}"}])
    start_s, end_s = now_ms // 1000 - 600, now_ms // 1000 + 60

    good = f"fields @message | filter @message like '{marker}'"
    unknown_cmd = good + " | frobnicate x"
    dangling = good + " | sort"

    code1, msg1 = _start_error(svc, logGroupNames=[group], startTime=start_s, endTime=end_s,
                               queryString=unknown_cmd)
    # Only the internal Request ID at the end of the message varies; the response does not expose it.
    assert code1 == "MalformedQueryException", f"unknown command: expected MalformedQueryException, got {code1!r} {msg1!r}"
    m1 = re.match(r"unexpected symbol found frobnicate at line 1 and position (\d+)", msg1)
    assert m1, f"unknown command: message must name the token 'frobnicate', got {msg1!r}"
    expected1 = _logs_refusal(
        f"unexpected symbol found frobnicate at line 1 and position {m1.group(1)}",
        "MalformedQueryException",
        msg1,
    )
    assert msg1 == expected1, f"unknown command: expected message {expected1!r}, got {msg1!r}"

    code2, msg2 = _start_error(svc, logGroupNames=[group], startTime=start_s, endTime=end_s,
                               queryString=dangling)
    # Only the internal Request ID at the end of the message varies; the response does not expose it.
    assert code2 == "MalformedQueryException", f"dangling sort: expected MalformedQueryException, got {code2!r} {msg2!r}"
    m2 = re.match(r"unexpected symbol found <EOF> at line 1 and position (\d+)", msg2)
    assert m2, f"dangling sort: message must name <EOF>, got {msg2!r}"
    expected2 = _logs_refusal(
        f"unexpected symbol found <EOF> at line 1 and position {m2.group(1)}",
        "MalformedQueryException",
        msg2,
    )
    assert msg2 == expected2, f"dangling sort: expected message {expected2!r}, got {msg2!r}"

    # The service prefixes a rewritten SOURCE clause, so only the position difference is ours.
    delta_reported = int(m2.group(1)) - int(m1.group(1))
    delta_ours = len(dangling) - unknown_cmd.index("frobnicate")
    assert delta_reported == delta_ours, (
        f"error positions must track the offending token: reported delta {delta_reported}, "
        f"token moved {delta_ours} chars ({msg1!r} vs {msg2!r})"
    )

    # Neither refused query exists server-side.
    described = _described_strings(svc, group)
    phantom = [s for s in described if "frobnicate" in s or s.rstrip().endswith("| sort")]
    assert not phantom, f"a refused StartQuery left a visible query behind: {phantom!r}"

    # Positive control: the valid prefix runs and finds the planted event.
    ok = _query_until(svc, [group], start_s, end_s, good, lambda r: len(r["results"]) == 1,
                      what="positive control finds the planted event")
    assert _rows(ok) == [{"@message": f"hello {marker}"}], f"control rows {_rows(ok)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
