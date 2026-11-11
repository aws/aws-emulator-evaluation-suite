"""get-metric-data-insights-select-aggregates-per-group-and-admits-one-query."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-data-insights-select-aggregates-per-group-and-admits-one-query"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

_TWO_SELECTS = ("ValidationError", "Maximum number of queries (1) exceeded")
_EXCEEDED = {"Code": "MaxQueryTimeRangeExceeded", "Value": "Max time window exceeded for query"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; raise on timeout (TimeoutError if the run budget ended it)."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended the wait. Last result: {last!r}")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def expect_error(fn, code, message, label="call"):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message", ""))
        assert got == (code, message), f"{label}: expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"{label}: expected {(code, message)!r}, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Metrics Insights SELECT aggregates each GROUP BY group, matches SCHEMA's dimension set exactly and
    honours ORDER BY ... LIMIT; GetMetricData admits one SELECT per request beside MetricStat and math, and
    flags a 20-day SELECT window with a top-level MaxQueryTimeRangeExceeded message."""
    cw = ctx.client("cloudwatch", config=Config(read_timeout=20))
    # A custom namespace cannot be deleted (no DeleteMetric API); it ages out.
    namespace = ctx.unique_name("sim2real-cw-gmd-insights-")
    now = datetime.now(timezone.utc)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            *({"MetricName": "Load", "Dimensions": [{"Name": "Host", "Value": f"h{h}"}], "Timestamp": now,
               "Value": float(h * k)} for h in (1, 2, 3) for k in (1, 2, 3)),
            {"MetricName": "Load", "Timestamp": now, "Value": 7.0},
        ],
    )
    by_host = f'SCHEMA("{namespace}", Host)'
    stat = {"Id": "m", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Load",
                                                 "Dimensions": [{"Name": "Host", "Value": "h1"}]},
                                      "Period": 60, "Stat": "Sum"}}

    def sel(sql, qid="q", period=60):
        return {"Id": qid, "Expression": sql, "Period": period}

    def call(*queries, days=None):
        start = now - timedelta(days=days) if days else now - timedelta(minutes=15)
        return cw.get_metric_data(MetricDataQueries=list(queries), StartTime=start,
                                  EndTime=now + timedelta(minutes=5 if days else 2))

    def rows(response):
        return [(r["Id"], r["Values"]) for r in response["MetricDataResults"]]

    def values(sql):
        return [v for _, v in rows(call(sel(sql)))]

    def groups(sql):
        results = rows(call(sel(sql)))
        assert len(results) == 3, f"{sql}: expected one row per host (3), got {results!r}"
        assert all(qid == "q" for qid, _ in results), f"{sql}: expected every row to carry the query Id 'q', got {results!r}"
        return sorted(v for _, v in results)

    # Insights discovers a new series tens of seconds after MetricStat can read it (SCHEMA(ns) lagging
    # bare FROM), and an undiscovered series reads exactly like no data, so wait for the whole fixture.
    _poll_until(
        ctx,
        lambda: (sorted(rows(call(sel(f"SELECT COUNT(Load) FROM {by_host} GROUP BY Host")))),
                 values(f'SELECT SUM(Load) FROM "{namespace}"'), values(f'SELECT SUM(Load) FROM SCHEMA("{namespace}")')),
        lambda r: r == ([("q", [3.0])] * 3, [[43.0]], [[7.0]]),
        timeout_s=180.0, interval_s=3.0,
        description="Insights to see every fixture series (COUNT 3 per host, bare namespace 43, SCHEMA(ns) 7)",
    )

    sums = groups(f"SELECT SUM(Load) FROM {by_host} GROUP BY Host")
    assert sums == [[6.0], [12.0], [18.0]], f"expected the per-host SUMs 6, 12, 18, got {sums!r}"
    avgs = groups(f"SELECT AVG(Load) FROM {by_host} GROUP BY Host")
    assert avgs == [[2.0], [4.0], [6.0]], f"expected the per-host AVGs 2, 4, 6, got {avgs!r}"
    host_total = values(f"SELECT SUM(Load) FROM {by_host}")
    assert host_total == [[36.0]], f"expected SCHEMA(ns, Host) to sum only the Host series to 36, got {host_total!r}"

    top = values(f"SELECT SUM(Load) FROM {by_host} GROUP BY Host ORDER BY SUM() DESC LIMIT 2")
    assert top == [[18.0], [12.0]], f"expected ORDER BY SUM() DESC LIMIT 2 to return 18 then 12, got {top!r}"
    ascending = values(f"SELECT SUM(Load) FROM {by_host} GROUP BY Host ORDER BY SUM() ASC")
    assert ascending == [[6.0], [12.0], [18.0]], f"expected ORDER BY SUM() ASC to return 6, 12, 18, got {ascending!r}"

    expect_error(
        lambda: call(sel(f"SELECT SUM(Load) FROM {by_host}", "q1"), sel(f"SELECT MAX(Load) FROM {by_host}", "q2")),
        *_TWO_SELECTS, label="two SELECTs",
    )
    mixed = rows(call(sel(f"SELECT SUM(Load) FROM {by_host}"), stat, {"Id": "e", "Expression": "m * 2"}))
    assert sorted(qid for qid, _ in mixed) == ["e", "m", "q"], f"expected exactly the rows q, m, e, got {mixed!r}"
    assert dict(mixed) == {"q": [36.0], "m": [6.0], "e": [12.0]}, (
        f"expected one SELECT beside a MetricStat and math to return q 36, m 6, e 12, got {mixed!r}"
    )

    hourly = sel(f"SELECT SUM(Load) FROM {by_host}", period=3600)
    long_stat = {**stat, "MetricStat": {**stat["MetricStat"], "Period": 3600}}
    for label, query, days, flagged, expected in [("20-day SELECT", hourly, 20, True, [("q", [36.0])]),
                                                  ("1-day SELECT", hourly, 1, False, [("q", [36.0])]),
                                                  ("20-day MetricStat-only", long_stat, 20, False, [("m", [6.0])])]:
        response = call(query, days=days)
        if flagged:
            assert response["Messages"] == [_EXCEEDED], (
                f"{label}: expected exactly {[_EXCEEDED]!r} in Messages, got {response['Messages']!r}"
            )
        else:
            assert response["Messages"] == [], f"{label}: expected no top-level Messages, got {response['Messages']!r}"
        assert rows(response) == expected, f"{label}: expected the rows {expected!r}, got {rows(response)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
