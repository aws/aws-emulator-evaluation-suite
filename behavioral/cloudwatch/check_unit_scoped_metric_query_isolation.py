"""unit-scoped-metric-query-isolation."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "unit-scoped-metric-query-isolation"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")
# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Unit-scoped query returns only that unit's datapoints and a never-published Unit returns none;
    an omitted Unit never sums across units (GetMetricStatistics returns one datapoint per unit,
    GetMetricData one series): a store that merges units alarms on numbers no datapoint had."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-unit-")
    metric = "Duration"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(minutes=10)
    end = now + timedelta(minutes=5)

    cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {"MetricName": metric, "Timestamp": now, "Value": 100.0, "Unit": "Milliseconds"},
            {"MetricName": metric, "Timestamp": now, "Value": 7.0, "Unit": "Count"},
        ],
    )

    def stats(unit):
        kwargs = dict(
            Namespace=ns,
            MetricName=metric,
            StartTime=start,
            EndTime=end,
            Period=3600,
            Statistics=["Sum", "SampleCount"],
        )
        if unit is not None:
            kwargs["Unit"] = unit
        return cw.get_metric_statistics(**kwargs).get("Datapoints", [])

    def data(unit):
        """GetMetricData over the same metric, optionally scoped to a unit."""
        metric_stat = {
            "Metric": {"Namespace": ns, "MetricName": metric},
            "Period": 3600,
            "Stat": "Sum",
        }
        if unit is not None:
            metric_stat["Unit"] = unit
        result = cw.get_metric_data(
            MetricDataQueries=[{"Id": "u1", "MetricStat": metric_stat, "ReturnData": True}],
            StartTime=start,
            EndTime=end,
        )["MetricDataResults"]
        assert len(result) == 1, f"one query must yield one MetricDataResult, got {result}"
        return result[0]

    # Positive anchors: each unit resolves to its own series.
    ms = _poll_until(
        lambda: stats("Milliseconds"),
        lambda d: len(d) > 0,
        timeout_s=120,
        interval_s=3,
        description="the Milliseconds-unit datapoint to become queryable",
    )
    assert len(ms) == 1, f"Unit=Milliseconds must select exactly one series, got {ms}"
    assert ms[0]["Sum"] == 100.0, f"Unit=Milliseconds must return only the 100.0 datum, got {ms}"
    assert ms[0]["SampleCount"] == 1.0, f"expected SampleCount=1.0 for the Milliseconds series, got {ms}"
    assert ms[0]["Unit"] == "Milliseconds", (
        f"the datapoint must be stamped with the unit it was published under, got {ms[0].get('Unit')!r}"
    )

    cnt = _poll_until(
        lambda: stats("Count"),
        lambda d: len(d) > 0,
        timeout_s=90,
        interval_s=3,
        description="the Count-unit datapoint to become queryable",
    )
    assert len(cnt) == 1, f"Unit=Count must select exactly one series, got {cnt}"
    assert cnt[0]["Sum"] == 7.0, f"Unit=Count must return only the 7.0 datum, got {cnt}"
    assert cnt[0]["SampleCount"] == 1.0, f"expected SampleCount=1.0 for the Count series, got {cnt}"
    assert cnt[0]["Unit"] == "Count", cnt[0].get("Unit")

    # --- Omitting Unit does NOT aggregate: GetMetricStatistics returns one datapoint per
    # unit series, in the same Period bucket (verified -- see run()'s docstring) ---
    unscoped = _poll_until(
        lambda: stats(None),
        lambda d: len(d) == 2,
        timeout_s=90,
        interval_s=3,
        description="an unscoped query to return one datapoint per unit series",
    )
    by_unit = {d["Unit"]: d for d in unscoped}
    assert set(by_unit) == {"Count", "Milliseconds"}, (
        f"an unscoped GetMetricStatistics must keep the two unit series separate and stamp each "
        f"datapoint with its own Unit; got {sorted(by_unit)}"
    )
    assert by_unit["Count"]["Sum"] == 7.0, by_unit["Count"]
    assert by_unit["Milliseconds"]["Sum"] == 100.0, by_unit["Milliseconds"]
    # Each datapoint keeps its OWN SampleCount of 1: neither series absorbed the other's
    # sample. This is the assertion that fails an emulator storing one merged series.
    assert by_unit["Count"]["SampleCount"] == 1.0, by_unit["Count"]
    assert by_unit["Milliseconds"]["SampleCount"] == 1.0, by_unit["Milliseconds"]
    assert all(d["Sum"] != 107.0 for d in unscoped), (
        f"no datapoint may carry the cross-unit total 100+7=107 -- units are separate series, "
        f"not addends; got {unscoped}"
    )
    # Both datapoints land in the SAME bucket, so they are genuinely two co-timestamped
    # series rather than the same series read twice at different times.
    assert by_unit["Count"]["Timestamp"] == by_unit["Milliseconds"]["Timestamp"], (
        f"both unit series must report the same Period bucket, got "
        f"{by_unit['Count']['Timestamp']} vs {by_unit['Milliseconds']['Timestamp']}"
    )

    # --- The GetMetricData read path: Unit scopes there too, and omitting it resolves to a
    # SINGLE series rather than a sum ---
    assert data("Milliseconds")["Values"] == [100.0], (
        f"a Unit-scoped MetricStat must select only the Milliseconds series, got "
        f"{data('Milliseconds')['Values']}"
    )
    assert data("Count")["Values"] == [7.0], data("Count")["Values"]
    unscoped_gmd = data(None)
    assert unscoped_gmd["Values"] == [7.0], (
        "a MetricStat that omits Unit must resolve to exactly ONE unit series (verified: the "
        "alphabetically first unit name, here Count, independent of publish order and stable "
        f"across repeated calls) and never the 107.0 cross-unit sum; got {unscoped_gmd['Values']}"
    )
    assert unscoped_gmd["StatusCode"] == "Complete", unscoped_gmd.get("StatusCode")
    assert unscoped_gmd["Label"] == metric, (
        f"the result's default Label is the metric name, got {unscoped_gmd.get('Label')!r}"
    )

    # --- Negative: never-published units must resolve to empty, not fall back ---
    for unit in ("Bytes", "Seconds", "None", "Percent", "Microseconds"):
        got = stats(unit)
        assert got == [], (
            f"Unit={unit!r} was never published for this metric, so the query must return no "
            f"datapoints -- Unit is a series selector, not a decoration; got {got}"
        )
    # The same refusal on the GetMetricData path, where it is an EMPTY series rather than an
    # error: the result is still returned, Complete, with no values at all.
    empty = data("Bytes")
    assert empty["Values"] == [], (
        f"Unit=Bytes was never published, so the MetricStat must select nothing rather than "
        f"falling back to another unit's data; got {empty['Values']}"
    )
    assert empty["StatusCode"] == "Complete", (
        f"an unmatched unit is an empty result, not a partial or failed one, got "
        f"{empty.get('StatusCode')!r}"
    )

    # --- Control: the unit-scoped positives still hold after the negatives ---
    control = stats("Milliseconds")
    assert control and control[0]["Sum"] == 100.0, (
        f"Unit=Milliseconds must still return Sum=100.0 after the negatives, got {control}"
    )
    assert data("Count")["Values"] == [7.0], (
        f"the Count series must still resolve after the never-published queries, got "
        f"{data('Count')['Values']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
