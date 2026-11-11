"""metric-data-dimension-filtering."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metric-data-dimension-filtering"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """The same metric name written with two different dimension sets is tracked as two
    distinct time series: GetMetricStatistics filtered by one dimension set must not mix
    in values written under the other."""

    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehav")
    metric = "DimensionedMetric"
    now = datetime.now(timezone.utc).replace(microsecond=0)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric,
                "Dimensions": [{"Name": "Host", "Value": "host-1"}],
                "Timestamp": now,
                "Value": 10.0,
            },
            {
                "MetricName": metric,
                "Dimensions": [{"Name": "Host", "Value": "host-2"}],
                "Timestamp": now,
                "Value": 20.0,
            },
        ],
    )

    def probe(dim_value):
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            Dimensions=[{"Name": "Host", "Value": dim_value}],
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=300,
            Statistics=["Sum"],
        )
        return resp["Datapoints"]

    dp1 = _poll_until(lambda: probe("host-1"), lambda dp: len(dp) > 0, timeout_s=180.0, interval_s=10.0)
    dp2 = _poll_until(lambda: probe("host-2"), lambda dp: len(dp) > 0, timeout_s=60.0, interval_s=10.0)
    if not dp1 or not dp2:
        raise AssertionError(
            f"metric data did not land within the polling window: host-1 datapoints={dp1!r}, "
            f"host-2 datapoints={dp2!r}"
        )

    assert abs(dp1[0]["Sum"] - 10.0) < 1e-6, (
        f"host-1 series (Dimensions=[Host=host-1]) contaminated by host-2's write: "
        f"expected Sum=10.0, got Sum={dp1[0]['Sum']} ({dp1})"
    )
    assert abs(dp2[0]["Sum"] - 20.0) < 1e-6, (
        f"host-2 series (Dimensions=[Host=host-2]) contaminated by host-1's write: "
        f"expected Sum=20.0, got Sum={dp2[0]['Sum']} ({dp2})"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
