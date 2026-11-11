"""deep-logs-1-logsql-sql-group-by-having-matches-hand-computation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-1-logsql-sql-group-by-having-matches-hand-computation"
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


# (svc, ms) — hand computation below the table.
_EVENTS = [
    ("api", 10), ("api", 20), ("api", 30),
    ("db", 100), ("db", 200),
    ("web", 50),
    ("auth", 3), ("auth", 40),
    ("cache", 1), ("cache", 2),
]
# WHERE ms > 5 keeps: api {10,20,30}, db {100,200}, web {50}, auth {40}; cache is gone.
# HAVING n > 1 keeps api (n=3, total=60) and db (n=2, total=300); web and auth (n=1) drop.
# HAVING total > 100 keeps only db.


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """A SQL StartQuery that names its log group only in FROM returns exactly the hand-computed (svc, COUNT,
    SUM) rows for planted events, with recordsMatched 7, for two different HAVING predicates; each query
    moves Scheduled -> Running -> Complete without going back.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-logsql-sql-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    base = int(time.time() * 1000) - 180_000
    events = [{"timestamp": base + i * 1000, "message": json.dumps({"svc": s, "ms": ms})}
              for i, (s, ms) in enumerate(_EVENTS)]
    svc.create_log_stream(logGroupName=group, logStreamName="a")
    svc.create_log_stream(logGroupName=group, logStreamName="b")
    put_a = svc.put_log_events(logGroupName=group, logStreamName="a", logEvents=events[:5])
    put_b = svc.put_log_events(logGroupName=group, logStreamName="b", logEvents=events[5:])
    for put in (put_a, put_b):
        assert not put.get("rejectedLogEventsInfo"), f"planted events were rejected: {put!r}"
    window = (base // 1000 - 60,)

    sql = (f"SELECT svc, COUNT(*) AS n, SUM(ms) AS total FROM `{group}` "
           "WHERE ms > 5 GROUP BY svc HAVING n > 1 ORDER BY svc")
    resp, seen = _query_until_scanned(svc, window, len(_EVENTS), what="SQL HAVING n > 1",
                                      queryLanguage="SQL", queryString=sql)
    rows = _rows(resp)
    assert rows == [{"svc": "api", "n": "3", "total": "60"}, {"svc": "db", "n": "2", "total": "300"}], (
        f"SQL GROUP BY/HAVING n > 1 returned {rows!r}; hand computation is api(3,60), db(2,300) in that order "
        f"(web and auth have n=1 after WHERE, cache is removed by WHERE)"
    )
    assert resp["statistics"]["recordsMatched"] == 7.0, (
        f"WHERE ms > 5 matches 7 of 10 planted events, statistics say {resp['statistics']!r}"
    )

    sql2 = (f"SELECT svc, COUNT(*) AS n, SUM(ms) AS total FROM `{group}` "
            "WHERE ms > 5 GROUP BY svc HAVING total > 100 ORDER BY svc")
    resp2, _ = _query_until_scanned(svc, window, len(_EVENTS), what="SQL HAVING total > 100",
                                    queryLanguage="SQL", queryString=sql2)
    rows2 = _rows(resp2)
    assert rows2 == [{"svc": "db", "n": "2", "total": "300"}], (
        f"SQL HAVING total > 100 returned {rows2!r}; only db (sum 300) exceeds 100"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
