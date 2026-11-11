"""extended-statistics-percentile-query."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extended-statistics-percentile-query"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']


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


def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so an emulator accepting input AWS refuses is never reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics for p0.0/p50/p90/p100 over the values 10, 20, ..., 100 returns only
    those keys, non-decreasing, with p0.0 = 10, p100 = 100, p50 in [50, 60], p90 in [90, 100] and
    no classic statistic; GetMetricData's p90 matches, and p101 fails with InvalidParameterValue."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-pct-")
    metric = "RequestLatency"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    # 10 distinct values, all inside one 1-hour aggregation bucket.
    values = [float(v) for v in range(10, 101, 10)]  # 10,20,...,100
    start = now - timedelta(minutes=30)
    end = now + timedelta(minutes=5)

    cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {
                "MetricName": metric,
                "Timestamp": now - timedelta(seconds=60 + i),
                "Value": v,
                "Unit": "Milliseconds",
            }
            for i, v in enumerate(values)
        ],
    )

    def probe():
        return cw.get_metric_statistics(
            Namespace=ns,
            MetricName=metric,
            StartTime=start,
            EndTime=end,
            Period=3600,
            ExtendedStatistics=["p0.0", "p50", "p90", "p100"],
        ).get("Datapoints", [])

    dps = _poll_until(
        probe,
        lambda d: len(d) == 1 and len(d[0].get("ExtendedStatistics", {})) == 4,
        timeout_s=150,
        interval_s=5,
        description="all 10 samples aggregated into one bucket with 4 percentiles",
    )
    dp = dps[0]
    ext = dp["ExtendedStatistics"]
    assert set(ext) == {"p0.0", "p50", "p90", "p100"}, (
        f"the ExtendedStatistics map must be keyed by exactly the requested labels, got {sorted(ext)}"
    )
    assert ext["p0.0"] == min(values), (
        f"p0.0 must equal the distribution minimum {min(values)}, got {ext['p0.0']}"
    )
    assert ext["p100"] == max(values), (
        f"p100 must equal the distribution maximum {max(values)}, got {ext['p100']}"
    )
    ordered = [ext["p0.0"], ext["p50"], ext["p90"], ext["p100"]]
    assert ordered == sorted(ordered), f"percentiles must be non-decreasing, got {ordered}"
    # p50 of 10..100 sits on/between the 5th and 6th samples; p90 on/between the 9th and 10th.
    assert 50.0 <= ext["p50"] <= 60.0, (
        f"p50 of {values} must fall in the [50, 60] sample bracket -- an emulator returning the "
        f"mean (55) is inside, one returning min/max/Average-of-nothing is not; got {ext['p50']}"
    )
    assert 90.0 <= ext["p90"] <= 100.0, (
        f"p90 of {values} must fall in the [90, 100] sample bracket, got {ext['p90']}"
    )

    # Shape fidelity / over-permissiveness: a percentile-only request must NOT
    # also return the classic statistics that were never asked for.
    for unrequested in ("Sum", "Average", "Minimum", "Maximum", "SampleCount"):
        assert unrequested not in dp, (
            f"a datapoint for an ExtendedStatistics-only request must not carry the unrequested "
            f"{unrequested} field; got keys {sorted(dp)}"
        )

    # The same percentile engine must back GetMetricData's Stat field.
    md = cw.get_metric_data(
        MetricDataQueries=[{
            "Id": "m1",
            "MetricStat": {
                "Metric": {"Namespace": ns, "MetricName": metric},
                "Period": 3600,
                "Stat": "p90",
            },
            "ReturnData": True,
        }],
        StartTime=start,
        EndTime=end,
        ScanBy="TimestampAscending",
    )["MetricDataResults"][0]
    assert md["Values"] and abs(md["Values"][0] - ext["p90"]) < 1e-6, (
        f"GetMetricData Stat='p90' must agree with GetMetricStatistics p90={ext['p90']}, "
        f"got {md['Values']}"
    )

    # --- Deep negative: a percentile outside p0.0..p100 is rejected ---
    code, message = _err(lambda: cw.get_metric_statistics(
        Namespace=ns,
        MetricName=metric,
        StartTime=start,
        EndTime=end,
        Period=3600,
        ExtendedStatistics=["p101"],
    ))
    assert code == "InvalidParameterValue", (
        f"a percentile above p100 must be rejected with InvalidParameterValue, not silently "
        f"clamped to p100; got {code!r}"
    )
    assert message == (
        "The value p101 for parameter ExtendedStatistics.member.1.<list element> is not supported."
    ), f"unexpected InvalidParameterValue message {message!r}"

    # --- Control: the valid percentile query is unaffected ---
    control = probe()
    assert control and control[0]["ExtendedStatistics"]["p90"] == ext["p90"], (
        f"the valid percentile query must still return p90={ext['p90']} after the rejection, "
        f"got {control}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
