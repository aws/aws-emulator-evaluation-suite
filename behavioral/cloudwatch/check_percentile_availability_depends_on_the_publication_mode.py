"""percentile-availability-depends-on-the-publication-mode."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "percentile-availability-depends-on-the-publication-mode"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

#: Arm A: ten identical raw values. Every percentile of a constant series is that constant under
#: any percentile method, so this arm pins an EXACT figure with no method ambiguity.
_RAW_VALUE = 7.0
_RAW_N = 10

#: Arm B: a weighted histogram whose p90 and p99 fall in different buckets by construction.
_HIST_VALUES = [10.0, 20.0]
_HIST_COUNTS = [95.0, 5.0]

#: Arm C: a statistic set with Min != Max. Percentiles are UNAVAILABLE for it.
_SPREAD_SET = {"SampleCount": 10.0, "Sum": 100.0, "Minimum": 1.0, "Maximum": 50.0}

#: Arm D: a statistic set satisfying the documented exception -- Min == Max and Sum == Min * n.
_FLAT_VALUE = 5.0
_FLAT_SET = {"SampleCount": 4.0, "Sum": 20.0, "Minimum": 5.0, "Maximum": 5.0}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Percentile availability depends on how data was published: p90 is 7.0 for ten raw 7.0 values, in
    [10, 20) with p99 near 20 for Values/Counts, absent for a statistic set with Min != Max (whose Sum
    reads back), and 5.0 for one with Min == Max and Sum == Min * SampleCount, as the docs state."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealPctlModeNs")
    # A closed minute in the recent past: a partial current bucket could legitimately hold fewer
    # samples than were published, which would make every arm's SampleCount unstable.
    stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=3)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": "RawValues", "Timestamp": stamp, "Value": _RAW_VALUE, "Unit": "Count"}
            for _ in range(_RAW_N)
        ],
    )
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": "Histogram",
                "Timestamp": stamp,
                "Values": _HIST_VALUES,
                "Counts": _HIST_COUNTS,
                "Unit": "Count",
            },
            {
                "MetricName": "SpreadStatisticSet",
                "Timestamp": stamp,
                "StatisticValues": _SPREAD_SET,
                "Unit": "Count",
            },
            {
                "MetricName": "FlatStatisticSet",
                "Timestamp": stamp,
                "StatisticValues": _FLAT_SET,
                "Unit": "Count",
            },
        ],
    )

    def _stats(metric: str, statistics: list[str]) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=stamp,
            EndTime=stamp + timedelta(seconds=60),
            Period=60,
            Statistics=statistics,
        )["Datapoints"]

    def _pctl(metric: str, percentiles: list[str]) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=stamp,
            EndTime=stamp + timedelta(seconds=60),
            Period=60,
            ExtendedStatistics=percentiles,
        )["Datapoints"]

    # --- every arm's raw aggregate must land before any percentile claim is made -------------- #
    # Ingest is asserted through the ONE projection every publication mode supports, so a missing
    # percentile below can never be confused with a missing datapoint.
    expected_counts = {
        "RawValues": float(_RAW_N),
        "Histogram": sum(_HIST_COUNTS),
        "SpreadStatisticSet": _SPREAD_SET["SampleCount"],
        "FlatStatisticSet": _FLAT_SET["SampleCount"],
    }
    _poll_until(
        lambda: {
            m: (_stats(m, ["SampleCount"]) or [{}])[0].get("SampleCount")
            for m in expected_counts
        },
        lambda seen: all(seen.get(m) == n for m, n in expected_counts.items()),
        timeout_s=180.0,
        interval_s=5.0,
        description=(
            f"all four publication modes visible in namespace {namespace!r} with SampleCounts "
            f"{expected_counts!r}"
        ),
    )

    # --- arm A: a constant raw series has an unambiguous percentile --------------------------- #
    raw = _pctl("RawValues", ["p90"])
    assert len(raw) == 1, (
        f"the raw-values metric returned {len(raw)} percentile buckets {raw!r}, expected exactly "
        f"1 for a single closed 60s period"
    )
    raw_p90 = raw[0]["ExtendedStatistics"]["p90"]
    assert abs(raw_p90 - _RAW_VALUE) < 1e-9, (
        f"p90 over {_RAW_N} raw values all equal to {_RAW_VALUE} is {raw_p90!r}; every percentile "
        f"of a constant series is that constant under nearest-rank AND under linear "
        f"interpolation, so there is no method ambiguity to hide behind"
    )

    # --- arm B: the weighted histogram places p90 and p99 in different buckets ---------------- #
    hist = _pctl("Histogram", ["p90", "p99"])
    assert len(hist) == 1, (
        f"the Values/Counts metric returned {len(hist)} percentile buckets {hist!r}, expected 1"
    )
    hist_stats = hist[0]["ExtendedStatistics"]
    lo, hi = _HIST_VALUES
    assert lo <= hist_stats["p90"] < hi, (
        f"p90 of the weighted multiset {_HIST_VALUES!r} x {_HIST_COUNTS!r} is "
        f"{hist_stats['p90']!r}; 95 of the 100 samples are {lo}, so the 90th percentile must sit "
        f"in the lower bucket -- [{lo}, {hi}). A target that ignored Counts and treated Values as "
        f"two unweighted samples reports {hi}"
    )
    # CloudWatch documents percentiles as an approximation: p99 over this multiset is about 19.84,
    # not the nearest-rank 20.0. The tolerance still rejects the Average (10.5) and the lower bucket.
    p99_tolerance = (hi - lo) * 0.2
    assert hi - p99_tolerance <= hist_stats["p99"] <= hi, (
        f"p99 of the weighted multiset is {hist_stats['p99']!r}; only the top 5 of 100 samples "
        f"are {hi}, so the 99th percentile must sit within [{hi - p99_tolerance!r}, {hi!r}] -- "
        f"the upper tail near {hi}, matching CloudWatch's documented percentile approximation "
        f"(measured on real AWS at ~19.84) -- not the Average "
        f"({sum(v * c for v, c in zip(_HIST_VALUES, _HIST_COUNTS)) / sum(_HIST_COUNTS)!r}) or the "
        f"lower bucket ({lo!r})"
    )
    assert hist_stats["p90"] < hist_stats["p99"], (
        f"p90 ({hist_stats['p90']!r}) is not below p99 ({hist_stats['p99']!r}); the two "
        f"percentiles were chosen to fall in different buckets, so equal answers mean the "
        f"distribution was collapsed to one value"
    )

    # --- arm C: the spread statistic set carries data but NO percentile ----------------------- #
    spread_raw = _stats("SpreadStatisticSet", ["Sum", "SampleCount", "Minimum", "Maximum"])
    assert len(spread_raw) == 1, (
        f"the spread statistic set returned {len(spread_raw)} buckets {spread_raw!r}, expected 1 "
        f"-- this read is the positive control proving the datum arrived"
    )
    got = spread_raw[0]
    assert got["Sum"] == _SPREAD_SET["Sum"] and got["SampleCount"] == _SPREAD_SET["SampleCount"], (
        f"the spread statistic set read back Sum={got['Sum']!r} SampleCount="
        f"{got['SampleCount']!r}, expected {_SPREAD_SET['Sum']!r}/"
        f"{_SPREAD_SET['SampleCount']!r}"
    )
    spread_pctl = _pctl("SpreadStatisticSet", ["p90"])
    assert spread_pctl == [], (
        f"ExtendedStatistics=['p90'] over a statistic set with Minimum={_SPREAD_SET['Minimum']} "
        f"!= Maximum={_SPREAD_SET['Maximum']} returned {spread_pctl!r}; CloudWatch needs raw "
        f"datapoints to compute percentiles and this aggregate carries no distribution, so the "
        f"documented answer is NO datapoint. Interpolating between Minimum and Maximum, or "
        f"returning Sum/SampleCount, or returning Maximum, are all wrong -- and the Sum read "
        f"immediately above proves the datum itself is present, so this emptiness is not latency"
    )

    # --- arm D: the documented exception makes the percentile available again ------------------ #
    flat = _pctl("FlatStatisticSet", ["p90"])
    assert len(flat) == 1, (
        f"a statistic set with Minimum == Maximum == {_FLAT_VALUE} and Sum == Minimum * "
        f"SampleCount satisfies the documented exception, so p90 must exist; got {flat!r}. "
        f"Without this arm, arm C would also pass against a target that never serves percentiles "
        f"for statistic sets at all"
    )
    flat_p90 = flat[0]["ExtendedStatistics"]["p90"]
    assert abs(flat_p90 - _FLAT_VALUE) < 1e-9, (
        f"p90 of a statistic set whose every sample is {_FLAT_VALUE} is {flat_p90!r}, expected "
        f"{_FLAT_VALUE!r}"
    )

    # --- control: the two available percentile paths still answer after the empty one ---------- #
    control = _pctl("RawValues", ["p90"])
    assert len(control) == 1 and abs(control[0]["ExtendedStatistics"]["p90"] - _RAW_VALUE) < 1e-9, (
        f"after arm C's empty read, p90 over the raw series returned {control!r}, expected the "
        f"single {_RAW_VALUE!r} bucket -- this rules out 'the percentile path stopped answering'"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip.

    Raises rather than returning the last value: on a metric-read surface 'the datapoint never
    arrived' is the only interesting failure, and returning it silently would let every downstream
    assertion grade an empty response.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
