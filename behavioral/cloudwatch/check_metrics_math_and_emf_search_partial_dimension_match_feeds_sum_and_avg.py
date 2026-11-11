"""metrics-math-and-emf-search-partial-dimension-match-feeds-sum-and-avg."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-search-partial-dimension-match-feeds-sum-and-avg"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]

# (Service, Host, value) -- values are distinct so each discovered series is identifiable.
_SERIES = [
    ("checkout", "h1", 10.0),
    ("checkout", "h2", 20.0),
    ("checkout", "h3", 60.0),
    ("checkout-legacy", "h1", 100.0),
    ("billing", "h1", 1000.0),
]


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """SEARCH quoted values match exactly, unquoted values match by token, and NOT excludes.

    SUM/AVG/MAX over the exact search collapse to one series (90/30/60); a {Service}-only
    schema matches nothing because partial matching is over values, never over keys.
    """
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-mme-search/")
    ts = (datetime.now(timezone.utc) - timedelta(minutes=2)).replace(second=0, microsecond=0)
    cw.put_metric_data(Namespace=ns, MetricData=[
        {"MetricName": "Latency", "Timestamp": ts, "Value": v,
         "Dimensions": [{"Name": "Service", "Value": svc}, {"Name": "Host", "Value": host}]}
        for svc, host, v in _SERIES
    ])
    schema = f"{{{ns},Service,Host}}"
    exprs = {
        "exact": f"SEARCH('{schema} Service=\"checkout\"', 'Sum', 60)",
        "token": f"SEARCH('{schema} Service=checkout', 'Sum', 60)",
        "notted": f"SEARCH('{schema} Service=\"checkout\" NOT Host=h3', 'Sum', 60)",
        "total": f"SUM(SEARCH('{schema} Service=\"checkout\"', 'Sum', 60))",
        "mean": f"AVG(SEARCH('{schema} Service=\"checkout\"', 'Sum', 60))",
        "peak": f"MAX(SEARCH('{schema} Service=\"checkout\"', 'Sum', 60))",
        "subset": f"SEARCH('{{{ns},Service}} checkout', 'Sum', 60)",
    }
    queries = [{"Id": qid, "Expression": e} for qid, e in exprs.items()]
    window = dict(StartTime=ts - timedelta(minutes=5), EndTime=ts + timedelta(minutes=5))

    # SEARCH resolves against the metric index, which lags ingestion.
    res = _poll(lambda: _read(cw, queries, window),
                lambda r: sorted(v for _, v in r.get("token", [])) == [10.0, 20.0, 60.0, 100.0]
                and r.get("total", [(None, None)])[0][1] == 90.0)

    def values(qid):
        return sorted(v for _, v in res.get(qid, []))

    assert values("exact") == [10.0, 20.0, 60.0], f"quoted exact search found {res.get('exact')!r}"
    assert values("token") == [10.0, 20.0, 60.0, 100.0], (
        f"unquoted token search found {res.get('token')!r}; expected checkout + checkout-legacy"
    )
    assert values("notted") == [10.0, 20.0], f"NOT Host=h3 search found {res.get('notted')!r}"
    for label, _ in res["exact"]:
        assert "checkout" in label and "legacy" not in label, f"exact search label {label!r}"
    for qid, want in (("total", 90.0), ("mean", 30.0), ("peak", 60.0)):
        assert [v for _, v in res.get(qid, [])] == [want], (
            f"{exprs[qid]} returned {res.get(qid)!r}; expected ONE series with value {want}"
        )
    assert res.get("subset", []) == [], (
        f"a {{Service}}-only schema matched {res.get('subset')!r}; no metric has that dimension set"
    )
    assert 1000.0 not in [v for rows in res.values() for _, v in rows], (
        f"billing leaked into a checkout search: {res!r}"
    )


def _read(cw, queries, window):
    """Id -> [(label, value)], one entry per returned series-with-a-value."""
    out: dict[str, list] = {}
    token = None
    while True:
        kw = dict(MetricDataQueries=queries, **window)
        if token:
            kw["NextToken"] = token
        resp = cw.get_metric_data(**kw)
        for r in resp["MetricDataResults"]:
            for v in r["Values"]:
                out.setdefault(r["Id"], []).append((r.get("Label", ""), v))
        token = resp.get("NextToken")
        if not token:
            return out


def _poll(fn, ready, timeout_s=250, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if ready(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"SEARCH never discovered the published series; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
