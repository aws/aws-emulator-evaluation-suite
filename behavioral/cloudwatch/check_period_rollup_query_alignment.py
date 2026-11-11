"""period-rollup-query-alignment."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "period-rollup-query-alignment"
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


def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics rolls five 1-minute points into five Period=60 buckets on the minute boundaries
    and one Period=300 bucket (Sum 15, SampleCount 5, Min 1, Max 5) stamped at the clock-aligned boundary
    even for a StartTime 30 s into it, and rejects Period=45 with InvalidParameterValue and its exact message."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-rollup-")
    metric = "Requests"
    now = datetime.now(timezone.utc)
    # Align base to an absolute 5-minute boundary safely in the past, so the whole
    # 5-minute window is closed and no partial bucket can appear.
    base = now.replace(minute=now.minute - (now.minute % 5), second=0, microsecond=0) - timedelta(minutes=15)
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    timestamps = [base + timedelta(minutes=i) for i in range(5)]

    cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {"MetricName": metric, "Timestamp": ts, "Value": v, "Unit": "Count"}
            for ts, v in zip(timestamps, values)
        ],
    )

    def stats(*, period, start, end):
        return cw.get_metric_statistics(
            Namespace=ns,
            MetricName=metric,
            StartTime=start,
            EndTime=end,
            Period=period,
            Statistics=["Sum", "SampleCount", "Minimum", "Maximum"],
        ).get("Datapoints", [])

    window_end = base + timedelta(minutes=5)

    # --- Period=60: one bucket per point, stamped on the minute boundaries ---
    fine = _poll_until(
        lambda: stats(period=60, start=base, end=window_end),
        lambda d: len(d) >= 5,
        timeout_s=150,
        interval_s=5,
        description="all five backdated datapoints to become queryable at Period=60",
    )
    assert len(fine) == 5, f"Period=60 over a 5-minute window with 5 points must give 5 buckets, got {fine}"
    fine.sort(key=lambda d: d["Timestamp"])
    got_ts = [d["Timestamp"] for d in fine]
    assert got_ts == timestamps, (
        f"Period=60 bucket timestamps must be the aligned minute boundaries {timestamps}, got {got_ts}"
    )
    got_sums = [d["Sum"] for d in fine]
    assert got_sums == values, f"each 1-minute bucket must carry its own point; expected {values}, got {got_sums}"
    assert all(d["SampleCount"] == 1.0 for d in fine), f"each 1-minute bucket holds one sample, got {fine}"

    # --- Period=300: the identical data collapses into exactly one bucket ---
    coarse = stats(period=300, start=base, end=window_end)
    assert len(coarse) == 1, (
        f"Period=300 over the same 5-minute window must collapse the 5 points into exactly 1 "
        f"bucket, got {len(coarse)}: {coarse}"
    )
    c = coarse[0]
    assert c["Sum"] == sum(values), f"expected the 5-minute bucket Sum={sum(values)}, got {c['Sum']}"
    assert c["SampleCount"] == 5.0, f"expected the 5-minute bucket SampleCount=5.0, got {c['SampleCount']}"
    assert c["Minimum"] == min(values), f"expected Minimum={min(values)}, got {c['Minimum']}"
    assert c["Maximum"] == max(values), f"expected Maximum={max(values)}, got {c['Maximum']}"
    assert c["Timestamp"] == base, (
        f"the Period=300 bucket must be stamped at the aligned 5-minute boundary {base}, got {c['Timestamp']}"
    )

    # --- Alignment: a mid-bucket StartTime must not move the bucket ---
    shifted = stats(period=300, start=base + timedelta(seconds=30), end=window_end)
    assert len(shifted) == 1, (
        f"a StartTime 30s into the bucket still selects exactly that one bucket, got {shifted}"
    )
    assert shifted[0]["Timestamp"] == base, (
        f"bucket boundaries are absolute-clock, not StartTime-relative: expected the bucket still "
        f"stamped {base}, got {shifted[0]['Timestamp']}"
    )
    assert shifted[0]["SampleCount"] == 5.0, (
        f"the aligned bucket carries all 5 samples regardless of where StartTime lands inside it, "
        f"got {shifted[0]['SampleCount']}"
    )

    # --- Deep negative: an unsupported Period is rejected, not rounded ---
    code, message = _client_error(lambda: stats(period=45, start=base, end=window_end))
    assert code == "InvalidParameterValue", (
        f"Period=45 is neither one of 1/5/10/30 nor a multiple of 60, so it must be rejected with "
        f"InvalidParameterValue rather than silently rounded to 60; got {code!r}"
    )
    expected_message = 'The parameter Period must be a value in the set [1, 5, 10, 20, 30].'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- Control: both valid Periods still resolve after the rejection ---
    assert len(stats(period=60, start=base, end=window_end)) == 5, "Period=60 must still return 5 buckets"
    control = stats(period=300, start=base, end=window_end)
    assert len(control) == 1 and control[0]["Sum"] == sum(values), (
        f"Period=300 must still return the single Sum={sum(values)} bucket, got {control}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
