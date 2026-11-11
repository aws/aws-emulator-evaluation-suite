"""deep-logs-1-logsql-sql-with-log-group-name-parameter-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-1-logsql-sql-with-log-group-name-parameter-rejected"
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


_ONLY_ONE = ("Only one of the parameters 'logGroupName', 'logGroupNames' or 'logGroupIdentifiers' "
             "may be specified in a request")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A SQL StartQuery with a FROM clause plus logGroupName, or plus logGroupNames, raises
    InvalidParameterException with the exact selector-conflict message and records no query; the same SQL
    with no selector parameter returns the hand-computed rows.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-logsql-sqlname-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    marker = ctx.unique_name("mk").replace("-", "")

    base = int(time.time() * 1000) - 180_000
    planted = [("api", 11), ("api", 22), ("api", 33), ("db", 44)]
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    put = svc.put_log_events(logGroupName=group, logStreamName="s", logEvents=[
        {"timestamp": base + i * 1000, "message": json.dumps({"svc": s, "ms": ms, "run": marker})}
        for i, (s, ms) in enumerate(planted)])
    assert not put.get("rejectedLogEventsInfo"), f"planted events were rejected: {put!r}"
    window = (base // 1000 - 60,)

    sql = (f"SELECT svc, COUNT(*) AS n, SUM(ms) AS total FROM `{group}` "
           f"WHERE run = '{marker}' GROUP BY svc ORDER BY svc")

    # The break: the same SQL plus logGroupName.
    code, msg = _start_error(svc, queryLanguage="SQL", queryString=sql, logGroupName=group,
                             startTime=window[0], endTime=int(time.time()) + 60)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r} {msg!r}"
    assert msg == _ONLY_ONE, f"message must name the selector conflict, got {msg!r}"

    # Same break through the list form.
    code2, msg2 = _start_error(svc, queryLanguage="SQL", queryString=sql, logGroupNames=[group],
                               startTime=window[0], endTime=int(time.time()) + 60)
    assert code2 == "InvalidParameterException", f"logGroupNames: expected InvalidParameterException, got {code2!r} {msg2!r}"
    assert msg2 == _ONLY_ONE, f"logGroupNames: message must name the selector conflict, got {msg2!r}"

    recorded = _recorded_with(svc, marker)
    assert recorded == [], f"a refused StartQuery still recorded a query: {recorded!r}"

    # Positive control: the identical SQL with no selector parameter runs and aggregates.
    resp, _ = _query_until_scanned(svc, window, len(planted), what="SQL with no selector",
                                   queryLanguage="SQL", queryString=sql)
    rows = _rows(resp)
    assert rows == [{"svc": "api", "n": "3", "total": "66"}, {"svc": "db", "n": "1", "total": "44"}], (
        f"SQL with no selector returned {rows!r}; hand computation is api(3,66), db(1,44)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
