"""metrics-math-and-emf-metric-math-time-series-functions-evaluate-per-datapoint."""
from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-metric-math-time-series-functions-evaluate-per-datapoint"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]

_A = [1.0, 3.0, 6.0, 10.0, 15.0]
_B = [5.0, 1.0, 4.0, 2.0, 3.0]
_SUM_A = sum(_A)
_AVG_A = _SUM_A / len(_A)

# id -> (expression, expected values, index of the first timestamp the result keeps)
_EXPECT = {
    "diff": ("DIFF(m1)", [2.0, 3.0, 4.0, 5.0], 1),
    "dtime": ("DIFF_TIME(m1)", [60.0, 60.0, 60.0, 60.0], 1),
    "rsum": ("RUNNING_SUM(m1)", [1.0, 4.0, 10.0, 20.0, 35.0], 0),
    "perrate": ("m1/PERIOD(m1)", [a / 60.0 for a in _A], 0),
    "cond": ("IF(m1>5, m1, 0)", [0.0, 0.0, 6.0, 10.0, 15.0], 0),
    "prec": ("m1+m2*2", [a + b * 2 for a, b in zip(_A, _B)], 0),
    "paren": ("(m1+m2)*2", [(a + b) * 2 for a, b in zip(_A, _B)], 0),
    "share": ("m1/SUM(m1)*100", [a / _SUM_A * 100 for a in _A], 0),
    "centred": ("m1-AVG(m1)", [a - _AVG_A for a in _A], 0),
    "flr": ("FLOOR(m1/4)", [float(math.floor(a / 4)) for a in _A], 0),
    "cel": ("CEIL(m1/4)", [float(math.ceil(a / 4)) for a in _A], 0),
    "summ": ("SUM(METRICS())", [a + b for a, b in zip(_A, _B)], 0),
    "maxm": ("MAX(METRICS())", [max(a, b) for a, b in zip(_A, _B)], 0),
    "top": ("FIRST(SORT(METRICS(), SUM, DESC))", _A, 0),
    "bottom": ("LAST(SORT(METRICS(), SUM, DESC))", _B, 0),
}


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """DIFF, DIFF_TIME, RUNNING_SUM, PERIOD, IF, FLOOR/CEIL, scalar broadcast, operator precedence,
    METRICS() and SORT/FIRST/LAST each return their closed-form values over two published series.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-mme-fn/")
    t0 = (datetime.now(timezone.utc) - timedelta(minutes=8)).replace(second=0, microsecond=0)
    stamps = [t0 + timedelta(minutes=i) for i in range(5)]
    cw.put_metric_data(Namespace=namespace, MetricData=(
        [{"MetricName": "A", "Timestamp": t, "Value": v} for t, v in zip(stamps, _A)]
        + [{"MetricName": "B", "Timestamp": t, "Value": v} for t, v in zip(stamps, _B)]
    ))

    queries = [
        {"Id": "m1", "ReturnData": False, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": "A"}, "Period": 60, "Stat": "Sum"}},
        {"Id": "m2", "ReturnData": False, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": "B"}, "Period": 60, "Stat": "Sum"}},
    ] + [{"Id": qid, "Expression": expr} for qid, (expr, _, _) in _EXPECT.items()]
    start, end = t0, t0 + timedelta(minutes=5)

    res = _poll_until_complete(cw, queries, start, end)
    assert set(res) == set(_EXPECT), (
        f"returned ids {sorted(res)!r}; expected only the expressions {sorted(_EXPECT)!r} "
        "(m1/m2 have ReturnData=False)"
    )
    for qid, (expr, want, first) in _EXPECT.items():
        got = res[qid]
        assert got["status"] == "Complete", f"{expr} StatusCode was {got['status']!r}"
        assert got["messages"] == [], f"{expr} carried messages {got['messages']!r}"
        assert len(got["values"]) == len(want) and all(
            math.isclose(g, w, rel_tol=1e-9, abs_tol=1e-9) for g, w in zip(got["values"], want)
        ), f"{expr} returned {got['values']!r}; expected {want!r}"
        assert got["timestamps"] == stamps[first:], (
            f"{expr} timestamps {[t.isoformat() for t in got['timestamps']]!r}; expected "
            f"{[t.isoformat() for t in stamps[first:]]!r}"
        )


def _read(cw, queries, start, end):
    out = {}
    token = None
    while True:
        kw = dict(MetricDataQueries=queries, StartTime=start, EndTime=end,
                  ScanBy="TimestampAscending")
        if token:
            kw["NextToken"] = token
        resp = cw.get_metric_data(**kw)
        for r in resp["MetricDataResults"]:
            slot = out.setdefault(r["Id"], {"values": [], "timestamps": [], "messages": []})
            slot["values"].extend(r["Values"])
            slot["timestamps"].extend(t.astimezone(timezone.utc) for t in r["Timestamps"])
            slot["messages"].extend(r.get("Messages") or [])
            slot["status"] = r["StatusCode"]
        token = resp.get("NextToken")
        if not token:
            return out


def _poll_until_complete(cw, queries, start, end, timeout_s=300, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _read(cw, queries, start, end)
        # Readiness = both raw series fully ingested (read through the identity RUNNING_SUM's
        # final value and LAST(SORT(...)) == B), never a guess at ingestion latency.
        if (last.get("rsum", {}).get("values", [])[-1:] == [_SUM_A]
                and last.get("bottom", {}).get("values") == _B):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"published series never became fully readable; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
