"""put-metric-data-out-of-order-timestamps-aggregated-correctly."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "put-metric-data-out-of-order-timestamps-aggregated-correctly"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Datapoints published out of chronological order each land in their own per-minute bucket with
    the published Sum in GetMetricStatistics (sorted by Timestamp here, as AWS does not order
    them)."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-cw-ooo-")
    metric_name = "OutOfOrderTest"
    dims = [{"Name": "Case", "Value": "ooo"}]

    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    t0 = now - timedelta(minutes=2)
    t1 = now - timedelta(minutes=1)
    t2 = now
    expected = {t0: 10.0, t1: 20.0, t2: 30.0}

    # Send out of chronological order: t1, then t0, then t2.
    for t, v in [(t1, 20.0), (t0, 10.0), (t2, 30.0)]:
        cw.put_metric_data(
            Namespace=ns,
            MetricData=[{"MetricName": metric_name, "Dimensions": dims, "Timestamp": t, "Value": v, "Unit": "Count"}],
        )

    datapoints = _poll_for_datapoints(ctx, ns, metric_name, dims, t0 - timedelta(seconds=30), t2 + timedelta(minutes=1), 3)
    by_ts = {dp["Timestamp"]: dp["Sum"] for dp in datapoints}
    for t, v in expected.items():
        assert by_ts.get(t) == v, f"expected Sum={v} at {t}, got {by_ts.get(t)} (all: {by_ts})"


def _poll_for_datapoints(ctx, namespace, metric_name, dimensions, start, end, expected_count, timeout_s=90.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    dps = []
    while time.monotonic() < deadline:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Sum"],
        )
        dps = resp.get("Datapoints", [])
        if len(dps) >= expected_count:
            return dps
        time.sleep(3)
    raise AssertionError(f"expected {expected_count} datapoints, only observed {len(dps)} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
