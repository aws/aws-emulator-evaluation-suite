"""deep-logs-1-logsql-ppl-backticked-fields-where-stats-match-hand-computation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-1-logsql-ppl-backticked-fields-where-stats-match-hand-computation"
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


# (stream, svc, ms, status-code)
_EVENTS = [
    ("a", "api", 10, 500), ("a", "api", 20, 200), ("a", "api", 30, 500), ("a", "db", 100, 500),
    ("a", "web", 7, 200),
    ("b", "db", 200, 500), ("b", "web", 5, 500), ("b", "api", 90, 500),
]


def _expected(stream, code):
    out = {}
    for st, s, ms, sc in _EVENTS:
        if st == stream and sc == code:
            n, total = out.get(s, (0, 0))
            out[s] = (n + 1, total + ms)
    return {s: {"svc": s, "n": str(n), "total": str(t)} for s, (n, t) in out.items()}


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """A PPL query over `source = logGroups(...)` filtering on backticked `@logStream` and
    `status-code` aggregates exactly the hand-computed per-svc buckets; unbackticked
    `status-code` (parsed as `status - code`) selects nothing."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-logsql-ppl-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    base = int(time.time() * 1000) - 180_000
    for stream in ("a", "b"):
        svc.create_log_stream(logGroupName=group, logStreamName=stream)
        evs = [{"timestamp": base + i * 1000,
                "message": json.dumps({"svc": s, "ms": ms, "status-code": sc})}
               for i, (st, s, ms, sc) in enumerate(_EVENTS) if st == stream]
        put = svc.put_log_events(logGroupName=group, logStreamName=stream, logEvents=evs)
        assert not put.get("rejectedLogEventsInfo"), f"planted events were rejected: {put!r}"
    window = (base // 1000 - 60,)

    src = f"source = `logGroups(logGroupIdentifier: ['{group}'])`"
    ppl = (f"{src} | where `@logStream` = 'a' and `status-code` = 500"
           " | stats count() as n, sum(ms) as total by svc")
    resp, seen = _query_until_scanned(svc, window, len(_EVENTS), what="PPL backticked where/stats",
                                      queryLanguage="PPL", queryString=ppl)
    got = {r.get("svc"): r for r in _rows(resp)}
    want = _expected("a", 500)
    assert want == {"api": {"svc": "api", "n": "2", "total": "40"},
                    "db": {"svc": "db", "n": "1", "total": "100"}}, f"hand computation drifted: {want!r}"
    assert got == want, (
        f"PPL where `@logStream`='a' and `status-code`=500 | stats by svc returned {got!r}, expected {want!r}"
    )
    assert resp["statistics"]["recordsMatched"] == 3.0, (
        f"3 planted events are in stream a with status-code 500; statistics say {resp['statistics']!r}"
    )

    # Stream b, same predicate shape: the @logStream filter is what selected the buckets above.
    ppl_b = (f"{src} | where `@logStream` = 'b' and `status-code` = 500"
             " | stats count() as n, sum(ms) as total by svc")
    resp_b, _ = _query_until_scanned(svc, window, len(_EVENTS), what="PPL stream b",
                                     queryLanguage="PPL", queryString=ppl_b)
    got_b = {r.get("svc"): r for r in _rows(resp_b)}
    assert got_b == _expected("b", 500), f"stream b buckets {got_b!r}, expected {_expected('b', 500)!r}"

    # Contrast: without backticks the hyphenated key is not a field reference.
    bare = f"{src} | where `@logStream` = 'a' and status-code = 500 | stats count() as n by svc"
    qid = svc.start_query(queryLanguage="PPL", queryString=bare,
                          startTime=window[0], endTime=int(time.time()) + 60)["queryId"]
    bare_resp, _ = _await(svc, qid)
    assert _rows(bare_resp) == [], (
        f"unbackticked status-code must not resolve to the `status-code` field, got rows {_rows(bare_resp)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
