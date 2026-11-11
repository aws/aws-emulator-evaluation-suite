"""logs-insights-semantics-stats-bin-one-minute-buckets-at-boundaries."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "logs-insights-semantics-stats-bin-one-minute-buckets-at-boundaries"
GROUP = 'insights'
SERVICES = ['logs']


_TERMINAL = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")


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
    """Ingestion is eventually consistent: re-run the query until its rows satisfy
    ``predicate`` or the budget is spent. Asserts content, never latency."""
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


def _put(svc, group, stream, events):
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=sorted(events, key=lambda e: e["timestamp"]),
    )


def _fmt_ts(ms):
    dt = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{ms % 1000:03d}"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`stats ... by bin(1m)` puts events at :59.999 and :00.000 into their own UTC minutes with counts
    1, 2 and 4, keys rendered as minute starts; sorting orders buckets and an un-aliased bin names its
    column `bin(1m)`.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-lisem-bin-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))

    m0 = (int(time.time() * 1000) // 60_000 - 6) * 60_000  # a minute start ~6 min ago
    m1, m2 = m0 + 60_000, m0 + 120_000
    plan = [  # (timestamp, value)
        (m0 + 59_999, 1),            # last millisecond of minute 0
        (m1, 10), (m1 + 30_500, 20),  # first millisecond of minute 1, and mid-minute
        (m2 + 1, 100), (m2 + 15_000, 200), (m2 + 30_000, 300), (m2 + 59_000, 400),
    ]
    _put(svc, group, "s", [{"timestamp": t, "message": f'{{"v": {v}}}'} for t, v in plan])
    start_s, end_s = m0 // 1000 - 60, int(time.time()) + 60

    want = {}
    for t, v in plan:
        key = _fmt_ts(t - t % 60_000)
        n, s = want.get(key, (0, 0))
        want[key] = (n + 1, s + v)
    expected = [{"b": k, "n": str(n), "s": str(s)} for k, (n, s) in sorted(want.items())]
    assert [e["n"] for e in expected] == ["1", "2", "4"], f"test plan itself is wrong: {expected!r}"

    q = "stats count(*) as n, sum(v) as s by bin(1m) as b | sort b asc"
    resp = _query_until(svc, [group], start_s, end_s, q,
                        lambda r: sum(int(x.get("n", 0)) for x in _rows(r)) == len(plan),
                        what=f"all {len(plan)} events bucketed")
    assert _rows(resp) == expected, f"bin(1m) buckets {_rows(resp)!r}, hand bucketing gives {expected!r}"

    desc = _rows(_run_query(svc, [group], start_s, end_s, q.replace("sort b asc", "sort b desc")))
    assert desc == list(reversed(expected)), f"sort b desc gave {desc!r}"

    unaliased = _rows(_run_query(svc, [group], start_s, end_s, "stats count(*) by bin(1m)"))
    unaliased = sorted(unaliased, key=lambda r: r.get("bin(1m)", ""))
    assert unaliased == [{"bin(1m)": e["b"], "count(*)": e["n"]} for e in expected], (
        f"un-aliased bin/count columns must be named by their expressions, got {unaliased!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
