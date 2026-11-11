"""deep-logs-1-logsql-sql-having-on-aggregate-expression-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-1-logsql-sql-having-on-aggregate-expression-rejected"
GROUP = 'insights'
SERVICES = ['logs']


_RANK = {"Scheduled": 0, "Running": 1, "Complete": 2}


def _await(svc, qid, *, timeout_s=120):
    """Poll GetQueryResults through Scheduled -> Running -> Complete.

    Only Complete is a result. Failed / Cancelled / Timeout / Unknown is a failure of the
    check, never an accepted outcome, and the trajectory must never move backwards.
    """
    seen = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = svc.get_query_results(queryId=qid)
        status = resp["status"]
        if not seen or seen[-1] != status:
            seen.append(status)
        if status not in ("Scheduled", "Running"):
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"query {qid} still {status!r} after {timeout_s}s (trajectory {seen!r})")
        time.sleep(0.5)
    assert seen[-1] == "Complete", (
        f"query {qid} ended {seen[-1]!r} (trajectory {seen!r}); a non-Complete query is never a result"
    )
    assert all(s in _RANK for s in seen), f"query {qid} reported a status outside the state machine: {seen!r}"
    ranks = [_RANK[s] for s in seen]
    assert ranks == sorted(ranks), f"query {qid} status moved backwards: {seen!r}"
    return resp, seen


def _rows(resp):
    return [{f["field"]: f["value"] for f in row if f["field"] != "@ptr"} for row in resp["results"]]


def _query_until_scanned(svc, window, n_events, *, what, budget_s=240, **kw):
    """Re-run the query until it has scanned every planted event (ingestion into the
    Insights index is eventually consistent, and a fresh group's first queries scan 0)."""
    deadline = time.monotonic() + budget_s
    while True:
        qid = svc.start_query(startTime=window[0], endTime=int(time.time()) + 60, **kw)["queryId"]
        resp, seen = _await(svc, qid)
        scanned = resp.get("statistics", {}).get("recordsScanned")
        if scanned == float(n_events):
            return resp, seen
        if time.monotonic() > deadline:
            raise AssertionError(
                f"{what}: scanned {scanned!r} of {n_events} planted events after {budget_s}s; rows={_rows(resp)!r}"
            )
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
    raise AssertionError(f"StartQuery accepted a request real AWS refuses: {kwargs!r} -> {resp!r}")


def _recorded_with(svc, marker):
    out = []
    for page in svc.get_paginator("describe_queries").paginate():
        out += [q.get("queryString", "") for q in page["queries"] if marker in q.get("queryString", "")]
    return out
def _java_sdk_wrapped(text, code, msg):
    """The message as CloudWatch Logs relays it from its query backend: ``text`` followed by
    the backend's error envelope. The backend's Request ID is per call, so it is lifted from
    ``msg``; every other byte is graded."""
    rid = msg.rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (f"{text} (Service: AWSLogs; Status Code: 400; Error Code: {code}; "
            f"Request ID: {rid}; Proxy: null)")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """SQL `HAVING COUNT(*) > 1` / `HAVING SUM(ms) > 50` are refused with MalformedQueryException
    (exact message, no query recorded), while `HAVING <alias>` over the same events returns the
    hand-computed rows; HAVING becomes a post-stats filter that may reference only stats outputs."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-logsql-having-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    marker = ctx.unique_name("mk").replace("-", "")

    base = int(time.time() * 1000) - 180_000
    planted = [("api", 10), ("api", 20), ("api", 30), ("db", 100), ("db", 200), ("web", 50)]
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    put = svc.put_log_events(logGroupName=group, logStreamName="s", logEvents=[
        {"timestamp": base + i * 1000, "message": json.dumps({"svc": s, "ms": ms, "run": marker})}
        for i, (s, ms) in enumerate(planted)])
    assert not put.get("rejectedLogEventsInfo"), f"planted events were rejected: {put!r}"
    window = (base // 1000 - 60,)
    head = (f"SELECT svc, COUNT(*) AS n, SUM(ms) AS total FROM `{group}` "
            f"WHERE run = '{marker}' GROUP BY svc")

    for having, translated in (("HAVING COUNT(*) > 1", "filtercount(*)>1"),
                               ("HAVING SUM(ms) > 50", "filtersum(ms)>50")):
        code, msg = _start_error(svc, queryLanguage="SQL", queryString=f"{head} {having}",
                                 startTime=window[0], endTime=int(time.time()) + 60)
        assert code == "MalformedQueryException", f"{having}: expected MalformedQueryException, got {code!r} {msg!r}"
        # The span is the HAVING clause's position in the translated pipeline; the group name
        # and marker have a fixed length, so it is the same on every run.
        expected = _java_sdk_wrapped(
            f"No aggregation function expression allowed: {translated} ([164,182])",
            "MalformedQueryException", msg)
        assert msg == expected, (
            f"{having}: message must name the aggregate-in-filter rule, expected {expected!r}, got {msg!r}"
        )
    recorded = _recorded_with(svc, marker)
    assert recorded == [], f"a refused StartQuery still recorded a query: {recorded!r}"

    # Positive control: the alias forms of the same two predicates.
    resp, _ = _query_until_scanned(svc, window, len(planted), what="HAVING n > 1",
                                   queryLanguage="SQL", queryString=f"{head} HAVING n > 1 ORDER BY svc")
    assert _rows(resp) == [{"svc": "api", "n": "3", "total": "60"}, {"svc": "db", "n": "2", "total": "300"}], (
        f"HAVING n > 1 returned {_rows(resp)!r}; hand computation is api(3,60), db(2,300)"
    )
    resp2, _ = _query_until_scanned(svc, window, len(planted), what="HAVING total > 50",
                                    queryLanguage="SQL", queryString=f"{head} HAVING total > 50 ORDER BY svc")
    assert _rows(resp2) == [{"svc": "api", "n": "3", "total": "60"}, {"svc": "db", "n": "2", "total": "300"}], (
        f"HAVING total > 50 returned {_rows(resp2)!r}; web (total 50) is not > 50"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
