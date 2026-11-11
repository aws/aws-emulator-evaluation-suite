"""metrics-math-and-emf-percentile-family-statistics-follow-the-raw-distribution."""
from __future__ import annotations

import math
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-percentile-family-statistics-follow-the-raw-distribution"
GROUP = "metric-statistics"
SERVICES = ["cloudwatch"]

# One datum carrying the raw values 1..100 -- the distribution every statistic below is read from.
_RAW = [float(i) for i in range(1, 101)]
# A statistic set with Minimum != Maximum carries no distribution at all.
_SPREAD_SET = {"SampleCount": 4.0, "Sum": 10.0, "Minimum": 1.0, "Maximum": 4.0}

_STATS = {
    "cnt": "SampleCount", "avg": "Average", "mn": "Minimum", "mx": "Maximum",
    "p50": "p50", "p90": "p90", "p99": "p99",
    "tm1090": "TM(10%:90%)", "iqm": "IQM", "wm1090": "WM(10%:90%)",
    "tmlow": "TM(:50)", "tclow": "TC(:50)", "prlow": "PR(:50)", "tslow": "TS(:50)",
    "tcband": "TC(10:20)",
}


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Percentile, trimmed and winsorized statistics of 1..100 land where the distribution puts them.

    PR(:50) == TC(:50)/SampleCount*100 and TS(:50) == TM(:50)*TC(:50); a spread statistic set
    returns no trimmed-family values while its Average is present.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-mme-pct/")
    ts = (datetime.now(timezone.utc) - timedelta(minutes=3)).replace(second=0, microsecond=0)

    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": "Dist", "Timestamp": ts, "Values": _RAW, "Unit": "Milliseconds"},
        {"MetricName": "Set", "Timestamp": ts, "StatisticValues": _SPREAD_SET},
    ])
    start, end = ts, ts + timedelta(seconds=60)

    dist_q = [{"Id": qid, "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Dist"},
                                         "Period": 60, "Stat": stat}}
              for qid, stat in _STATS.items()]
    got = _poll_gmd(cw, dist_q, start, end, lambda r: r["cnt"] == [100.0])
    v = {qid: vals[0] for qid, vals in got.items()}
    for qid, vals in got.items():
        assert len(vals) == 1, f"{_STATS[qid]} returned {vals!r}; expected exactly one datapoint"

    # Exact statistics over raw values.
    assert v["avg"] == 50.5, f"Average of 1..100 was {v['avg']!r}, expected 50.5"
    assert (v["mn"], v["mx"]) == (1.0, 100.0), f"Minimum/Maximum were {(v['mn'], v['mx'])!r}"

    # AWS computes percentiles from an approximating sketch, so bracket them, never pin them.
    assert 48.0 <= v["p50"] <= 53.0, f"p50 of 1..100 was {v['p50']!r}, expected ~50"
    assert 88.0 <= v["p90"] <= 92.0, f"p90 of 1..100 was {v['p90']!r}, expected ~90"
    assert 97.0 <= v["p99"] <= 100.0, f"p99 of 1..100 was {v['p99']!r}, expected ~99"
    assert v["p50"] < v["p90"] < v["p99"], (
        f"percentiles not monotone: p50={v['p50']!r} p90={v['p90']!r} p99={v['p99']!r}"
    )
    assert abs(v["p90"] - v["avg"]) > 30, f"p90 {v['p90']!r} is indistinguishable from Average"

    # Trimmed / winsorized family.
    assert 48.0 <= v["tm1090"] <= 53.0, f"TM(10%:90%) was {v['tm1090']!r}, expected ~50.5"
    assert 48.0 <= v["iqm"] <= 53.0, f"IQM was {v['iqm']!r}, expected ~50.5"
    assert 48.0 <= v["wm1090"] <= 53.0, f"WM(10%:90%) was {v['wm1090']!r}, expected ~50.5"
    assert 23.5 <= v["tmlow"] <= 27.5, f"TM(:50) was {v['tmlow']!r}, expected ~25.5 (mean of 1..50)"
    assert 47.0 <= v["tclow"] <= 53.0, f"TC(:50) was {v['tclow']!r}, expected ~50 values <= 50"
    assert 9.0 <= v["tcband"] <= 13.0, f"TC(10:20) was {v['tcband']!r}, expected ~11 values in [10,20]"
    assert v["tcband"] < v["tclow"], f"TC(10:20)={v['tcband']!r} not narrower than TC(:50)={v['tclow']!r}"

    # Exact identities: both sides come from the same sketch estimate.
    expect_pr = v["tclow"] / v["cnt"] * 100.0
    assert math.isclose(v["prlow"], expect_pr, rel_tol=1e-6), (
        f"PR(:50)={v['prlow']!r} != TC(:50)/SampleCount*100={expect_pr!r}"
    )
    expect_ts = v["tmlow"] * v["tclow"]
    assert math.isclose(v["tslow"], expect_ts, rel_tol=1e-6), (
        f"TS(:50)={v['tslow']!r} != TM(:50)*TC(:50)={expect_ts!r}"
    )

    # Effect absent: the trimmed family over a spread statistic set has no values.
    set_q = [{"Id": qid, "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Set"},
                                        "Period": 60, "Stat": stat}}
             for qid, stat in (("savg", "Average"), ("stm", "TM(10%:90%)"),
                               ("stc", "TC(:2)"), ("siqm", "IQM"))]
    sgot = _poll_gmd(cw, set_q, start, end, lambda r: r["savg"] == [2.5])
    assert sgot["savg"] == [2.5], f"statistic-set Average was {sgot['savg']!r}, expected [2.5]"
    for qid in ("stm", "stc", "siqm"):
        assert sgot[qid] == [], (
            f"{qid} over a statistic set with Minimum != Maximum returned {sgot[qid]!r}; "
            "a set carries no distribution, so the trimmed family must be absent"
        )


def _gmd(cw, queries, start, end):
    out = {q["Id"]: [] for q in queries}
    token = None
    while True:
        kw = dict(MetricDataQueries=queries, StartTime=start, EndTime=end,
                  ScanBy="TimestampAscending")
        if token:
            kw["NextToken"] = token
        resp = cw.get_metric_data(**kw)
        for r in resp["MetricDataResults"]:
            out[r["Id"]].extend(r["Values"])
        token = resp.get("NextToken")
        if not token:
            return out


def _poll_gmd(cw, queries, start, end, ready, timeout_s=300, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _gmd(cw, queries, start, end)
        if ready(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"published datapoints never became readable; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
