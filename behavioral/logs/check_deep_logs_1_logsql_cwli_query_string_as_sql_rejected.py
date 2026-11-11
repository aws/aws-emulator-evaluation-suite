"""deep-logs-1-logsql-cwli-query-string-as-sql-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-1-logsql-cwli-query-string-as-sql-rejected"
GROUP = 'insights'
SERVICES = ['logs']


_RANK = {"Scheduled": 0, "Running": 1, "Complete": 2}


def _await(svc, qid, *, timeout_s=120):
    """Poll GetQueryResults until Complete; any other terminal status, or a status moving
    backwards, fails the check."""
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


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """A Logs Insights QL query string submitted with queryLanguage='SQL' is refused at start and
    records no query; the same string runs as CWLI, and real SQL over the group returns the
    hand-computed aggregate, so the refusal is the dialect mismatch."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-logsql-cwlisql-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    marker = ctx.unique_name("mk").replace("-", "")

    base = int(time.time() * 1000) - 180_000
    planted = [("api", 10), ("api", 20), ("db", 30), ("db", 40), ("db", 50)]
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    put = svc.put_log_events(logGroupName=group, logStreamName="s", logEvents=[
        {"timestamp": base + i * 1000, "message": json.dumps({"svc": s, "ms": ms, "run": marker})}
        for i, (s, ms) in enumerate(planted)])
    assert not put.get("rejectedLogEventsInfo"), f"planted events were rejected: {put!r}"
    window = (base // 1000 - 60,)

    cwli = f"fields @timestamp, @message | filter @message like /{marker}/ | sort @timestamp asc"

    # The break: the same CWLI string, labelled SQL, no selector.
    code, msg = _start_error(svc, queryLanguage="SQL", queryString=cwli,
                             startTime=window[0], endTime=int(time.time()) + 60)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r} {msg!r}"
    assert msg == "Log group tag queries are not supported", (
        f"message must be the dialect-mismatch refusal real AWS returns, got {msg!r}"
    )
    recorded = _recorded_with(svc, marker)
    assert recorded == [], f"the refused StartQuery still recorded a query: {recorded!r}"

    # Positive control 1: the string is a valid CWLI query that sees all five events.
    ctl, _ = _query_until_scanned(svc, window, len(planted), what="CWLI control",
                                  logGroupName=group, queryLanguage="CWLI", queryString=cwli)
    assert len(ctl["results"]) == len(planted), (
        f"the CWLI string under queryLanguage='CWLI' returned {len(ctl['results'])} rows, planted {len(planted)}"
    )

    # Positive control 2: real SQL with no selector over the same group, exact aggregate.
    sql = (f"SELECT svc, COUNT(*) AS n, SUM(ms) AS total FROM `{group}` "
           f"WHERE run = '{marker}' GROUP BY svc ORDER BY svc")
    resp, _ = _query_until_scanned(svc, window, len(planted), what="SQL control",
                                   queryLanguage="SQL", queryString=sql)
    rows = _rows(resp)
    assert rows == [{"svc": "api", "n": "2", "total": "30"}, {"svc": "db", "n": "3", "total": "120"}], (
        f"SQL control returned {rows!r}; hand computation is api(2,30), db(3,120)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
