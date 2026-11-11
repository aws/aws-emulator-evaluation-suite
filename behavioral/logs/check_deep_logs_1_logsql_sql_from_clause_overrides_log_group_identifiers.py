"""deep-logs-1-logsql-sql-from-clause-overrides-log-group-identifiers."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-1-logsql-sql-from-clause-overrides-log-group-identifiers"
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


def _plant(svc, group, n, base):
    svc.create_log_stream(logGroupName=group, logStreamName="s")
    put = svc.put_log_events(logGroupName=group, logStreamName="s", logEvents=[
        {"timestamp": base + i * 1000, "message": json.dumps({"i": i, "group": group})} for i in range(n)])
    assert not put.get("rejectedLogEventsInfo"), f"planted events were rejected in {group}: {put!r}"


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """For SQL, the FROM clause decides what is scanned; a logGroupIdentifiers parameter is accepted
    but ignored: FROM group A with logGroupIdentifiers=[B] counts and scans only A's events."""
    svc = ctx.client("logs")
    a = ctx.unique_name("sim2real-logsql-froma-")
    b = ctx.unique_name("sim2real-logsql-fromb-")
    svc.create_log_group(logGroupName=a)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=a))
    svc.create_log_group(logGroupName=b)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=b))
    base = int(time.time() * 1000) - 180_000
    _plant(svc, a, 6, base)
    _plant(svc, b, 2, base)
    window = (base // 1000 - 60,)

    ra, _ = _query_until_scanned(svc, window, 6, what="SQL over A", queryLanguage="SQL",
                                 queryString=f"SELECT COUNT(*) AS n FROM `{a}`")
    assert _rows(ra) == [{"n": "6"}], f"SQL over A alone returned {_rows(ra)!r}"
    rb, _ = _query_until_scanned(svc, window, 2, what="SQL over B", queryLanguage="SQL",
                                 queryString=f"SELECT COUNT(*) AS n FROM `{b}`")
    assert _rows(rb) == [{"n": "2"}], f"SQL over B alone returned {_rows(rb)!r}"

    qid = svc.start_query(queryLanguage="SQL", queryString=f"SELECT COUNT(*) AS n FROM `{a}`",
                          logGroupIdentifiers=[b], startTime=window[0], endTime=int(time.time()) + 60)["queryId"]
    resp, _ = _await(svc, qid)
    assert _rows(resp) == [{"n": "6"}], (
        f"SQL FROM A with logGroupIdentifiers=[B] returned {_rows(resp)!r}; FROM must decide (6), "
        f"not the parameter (2) nor the union (8)"
    )
    assert resp["statistics"]["recordsScanned"] == 6.0, f"only A's 6 events may be scanned: {resp['statistics']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
