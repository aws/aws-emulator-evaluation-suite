"""get-metric-statistics-extended-percentile-accuracy."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-statistics-extended-percentile-accuracy"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics' ExtendedStatistics (p90) matches the expected percentile of raw
    datapoints published in a single PutMetricData call, within a generous tolerance that
    accommodates either nearest-rank or linear-interpolation percentile methods."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cwpct-ns-")
    metric_name = "RawSamples"

    # Anchor to a whole past minute so the single period [now, now+60s) cleanly contains every
    # raw sample and StartTime/EndTime rounding rules (see GetMetricStatistics docs) don't shift it.
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=2)
    values = [float(v) for v in range(1, 101)]  # 1..100
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": now,
                "Values": values,
                "Counts": [1.0] * len(values),
            }
        ],
    )

    start = now
    end = now + timedelta(seconds=60)
    datapoints = _poll_for_datapoints(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            # SampleCount is only populated on a Datapoint when requested via Statistics;
            # ExtendedStatistics alone omits it, so ask for both (empirically CloudWatch allows
            # combining Statistics and ExtendedStatistics in one GetMetricStatistics call).
            Statistics=["SampleCount"],
            ExtendedStatistics=["p90"],
        ),
        timeout_s=60,
    )

    assert datapoints, "GetMetricStatistics returned no datapoints for the published raw samples"
    dp = datapoints[0]
    assert dp["SampleCount"] == 100, f"expected 100 raw samples aggregated into the period, got {dp['SampleCount']}"
    p90 = dp["ExtendedStatistics"]["p90"]
    assert abs(p90 - 90) <= 3, f"p90 of the integers 1..100 should be close to 90, GetMetricStatistics returned {p90}"


def _poll_for_datapoints(fn, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    datapoints = []
    while time.monotonic() < deadline:
        datapoints = fn().get("Datapoints", [])
        if datapoints:
            return datapoints
        time.sleep(interval_s)
    return datapoints


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
