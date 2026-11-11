"""metrics-math-and-emf-period-buckets-anchor-at-minute-rounded-start-time."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-period-buckets-anchor-at-minute-rounded-start-time"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Period buckets start at StartTime rounded down to the minute, not at clock period multiples.

    GetMetricData and GetMetricStatistics return the same bucket stamps and sums.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-mme-align/")
    now = datetime.now(timezone.utc) - timedelta(minutes=20)
    base = now.replace(minute=now.minute - now.minute % 10, second=0, microsecond=0)
    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": "Ticks", "Timestamp": base + timedelta(minutes=i), "Value": float(i + 1)}
        for i in range(10)
    ])

    def m(minutes: float) -> datetime:
        return base + timedelta(minutes=minutes)

    # Readiness: the full series is visible at Period=60 (sum 55 over ten points).
    _poll(lambda: _gmd(cw, namespace, m(0), m(10), 60),
          lambda b: sum(v for _, v in b) == 55.0 and len(b) == 10)

    # CloudWatch rounds StartTime down to the whole minute for data under 15 days old;
    # Period=120 from B+1m yields odd-minute buckets that no 120 s clock grid contains.
    cases = [
        ("Period=300 from B+2m", m(2), 300, [(m(2), 25.0), (m(7), 27.0)]),
        ("Period=300 from B+2m30s", m(2.5), 300, [(m(2), 25.0), (m(7), 27.0)]),
        ("Period=120 from B+1m", m(1), 120,
         [(m(1), 5.0), (m(3), 9.0), (m(5), 13.0), (m(7), 17.0), (m(9), 10.0)]),
    ]
    for label, start, period, want in cases:
        end = m(12)
        got = _gmd(cw, namespace, start, end, period)
        assert got == want, (
            f"GetMetricData {label}: buckets {[(t.isoformat(), v) for t, v in got]!r}; "
            f"expected {[(t.isoformat(), v) for t, v in want]!r}"
        )
        gms = _gms(cw, namespace, start, end, period)
        assert gms == want, (
            f"GetMetricStatistics {label}: buckets {[(t.isoformat(), v) for t, v in gms]!r}; "
            f"expected {[(t.isoformat(), v) for t, v in want]!r}"
        )

    # The clock-aligned alternative really is different, so the assertions above discriminate.
    clock = _gmd(cw, namespace, m(0), m(10), 300)
    assert clock == [(m(0), 15.0), (m(5), 40.0)], f"B-anchored Period=300 gave {clock!r}"


def _gmd(cw, namespace, start, end, period):
    resp = cw.get_metric_data(
        MetricDataQueries=[{"Id": "t", "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": "Ticks"},
            "Period": period, "Stat": "Sum"}}],
        StartTime=start, EndTime=end, ScanBy="TimestampAscending",
    )
    (r,) = resp["MetricDataResults"]
    return [(t.astimezone(timezone.utc), v) for t, v in zip(r["Timestamps"], r["Values"])]


def _gms(cw, namespace, start, end, period):
    dps = cw.get_metric_statistics(Namespace=namespace, MetricName="Ticks", StartTime=start,
                                   EndTime=end, Period=period, Statistics=["Sum"])["Datapoints"]
    return sorted((d["Timestamp"].astimezone(timezone.utc), d["Sum"]) for d in dps)


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
