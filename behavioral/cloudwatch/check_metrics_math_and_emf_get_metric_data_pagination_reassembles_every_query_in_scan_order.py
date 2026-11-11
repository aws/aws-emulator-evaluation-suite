"""metrics-math-and-emf-get-metric-data-pagination-reassembles-every-query-in-scan-order."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-get-metric-data-pagination-reassembles-every-query-in-scan-order"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

_SERIES = {"A": [1.0, 3.0, 6.0, 10.0, 15.0], "B": [5.0, 1.0, 4.0, 2.0, 3.0],
           "C": [7.0, 7.5, 8.0, 8.5, 9.0]}
_MAX_DP = 7


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Six queries read with MaxDatapoints=7 span >= 5 pages of <= 7 values, report PartialData until
    Complete, and reassemble exactly to the unpaginated response in both ScanBy orders.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-mme-page/")
    t0 = (datetime.now(timezone.utc) - timedelta(minutes=8)).replace(second=0, microsecond=0)
    stamps = [t0 + timedelta(minutes=i) for i in range(5)]
    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": name, "Timestamp": t, "Value": v}
        for name, vals in _SERIES.items() for t, v in zip(stamps, vals)
    ])
    queries = [
        {"Id": f"{name.lower()}{stat[:3].lower()}", "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": name}, "Period": 60, "Stat": stat}}
        for name in _SERIES for stat in ("Sum", "Maximum")
    ]
    window = dict(StartTime=t0, EndTime=t0 + timedelta(minutes=5))
    total = sum(len(v) for v in _SERIES.values()) * 2

    for scan in ("TimestampDescending", "TimestampAscending"):
        order = list(reversed(stamps)) if scan == "TimestampDescending" else list(stamps)
        single = _poll(lambda s=scan: cw.get_metric_data(MetricDataQueries=queries, ScanBy=s,
                                                         **window),
                       lambda r: sum(len(x["Values"]) for x in r["MetricDataResults"]) == total)
        assert "NextToken" not in single, f"unpaginated read still paginated: {single.get('NextToken')!r}"
        whole = {r["Id"]: (r["Values"], [t.astimezone(timezone.utc) for t in r["Timestamps"]])
                 for r in single["MetricDataResults"]}
        for q in queries:
            name = q["MetricStat"]["Metric"]["MetricName"]
            want = [v for _, v in sorted(zip(stamps, _SERIES[name]),
                                         reverse=scan == "TimestampDescending")]
            assert whole[q["Id"]] == (want, order), (
                f"{scan} unpaginated {q['Id']} was {whole[q['Id']]!r}; expected {(want, order)!r}"
            )

        # How AWS packs pages is not query-by-query, so only client-relied invariants are asserted.
        pages = []
        token = None
        while True:
            kw = dict(MetricDataQueries=queries, ScanBy=scan, MaxDatapoints=_MAX_DP, **window)
            if token:
                kw["NextToken"] = token
            resp = cw.get_metric_data(**kw)
            pages.append(resp["MetricDataResults"])
            token = resp.get("NextToken")
            if not token:
                break
            assert len(pages) <= 40, f"pagination did not terminate after {len(pages)} pages"

        assert len(pages) >= -(-total // _MAX_DP), (
            f"{scan}: {total} datapoints at MaxDatapoints={_MAX_DP} came back in {len(pages)} pages"
        )
        joined: dict[str, tuple[list, list]] = {}
        statuses: dict[str, list[str]] = {}
        for i, page in enumerate(pages):
            n = sum(len(r["Values"]) for r in page)
            assert n <= _MAX_DP, f"{scan} page {i} carried {n} values > MaxDatapoints={_MAX_DP}"
            for r in page:
                vals, ts = joined.setdefault(r["Id"], ([], []))
                vals.extend(r["Values"])
                ts.extend(t.astimezone(timezone.utc) for t in r["Timestamps"])
                statuses.setdefault(r["Id"], []).append(r["StatusCode"])
        assert joined == whole, (
            f"{scan}: pages reassembled to {joined!r}; unpaginated read was {whole!r}"
        )
        for qid, seen in statuses.items():
            assert seen[-1] == "Complete" and all(s == "PartialData" for s in seen[:-1]), (
                f"{scan}: {qid} StatusCode sequence across pages was {seen!r}"
            )


def _poll(fn, ready, timeout_s=300, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if ready(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"published series never became fully readable; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
