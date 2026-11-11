"""partial-dimension-query-returns-no-datapoints."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "partial-dimension-query-returns-no-datapoints"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics and GetMetricData match a metric only by its complete dimension set: the exact
    set returns Sum 42.0, while a subset, no dimensions or a superset return no datapoints (GetMetricData:
    empty Values, StatusCode Complete), because CloudWatch does not roll up across dimension combinations."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-behav-cwprobe-ns-dimexact-")
    metric = "Latency"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(minutes=10)
    end = now + timedelta(minutes=5)
    full_dims = [{"Name": "Service", "Value": "checkout"}, {"Name": "Host", "Value": "web01"}]

    cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {
                "MetricName": metric,
                "Timestamp": now,
                "Value": 42.0,
                "Unit": "Milliseconds",
                "Dimensions": full_dims,
            }
        ],
    )

    def stats(dims):
        kwargs = dict(
            Namespace=ns,
            MetricName=metric,
            StartTime=start,
            EndTime=end,
            Period=3600,
            Statistics=["Sum", "SampleCount"],
        )
        if dims is not None:
            kwargs["Dimensions"] = dims
        return cw.get_metric_statistics(**kwargs).get("Datapoints", [])

    # Positive anchor: the exact, complete dimension set resolves the series.
    exact = _poll_until(
        lambda: stats(full_dims),
        lambda dps: len(dps) > 0,
        timeout_s=120,
        interval_s=3,
        description="the fully-dimensioned datapoint to become queryable",
    )
    assert exact[0]["Sum"] == 42.0, f"expected Sum=42.0 for the exact dimension set, got {exact}"
    assert exact[0]["SampleCount"] == 1.0, f"expected SampleCount=1.0, got {exact}"

    # Negative 1-3: every non-exact dimension set must resolve to a DIFFERENT
    # (empty) timeseries. The datapoint is already proven ingested above, so an
    # empty result here cannot be explained by propagation lag.
    for label, dims in (
        ("first dimension only", [{"Name": "Service", "Value": "checkout"}]),
        ("second dimension only", [{"Name": "Host", "Value": "web01"}]),
        ("no dimensions at all", []),
    ):
        got = stats(dims)
        assert got == [], (
            f"GetMetricStatistics with {label} must resolve to a distinct, empty timeseries -- "
            f"CloudWatch never rolls up across dimension combinations; got {got}"
        )

    # Negative 4: a SUPERSET is also a different series, not a narrowing filter.
    superset = stats(full_dims + [{"Name": "Region", "Value": "us-west-2"}])
    assert superset == [], (
        f"GetMetricStatistics with a superset dimension set must return nothing, got {superset}"
    )

    # Negative 5: the same rule on the second read path (GetMetricData / MetricStat).
    def metric_data(dims):
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {"Namespace": ns, "MetricName": metric, "Dimensions": dims},
                        "Period": 3600,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            ],
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        )
        return resp["MetricDataResults"][0]

    md_exact = _poll_until(
        lambda: metric_data(full_dims),
        lambda r: len(r.get("Values", [])) > 0,
        timeout_s=90,
        interval_s=3,
        description="GetMetricData to resolve the fully-dimensioned series",
    )
    assert md_exact["Values"] == [42.0], f"expected GetMetricData Values=[42.0], got {md_exact['Values']}"

    md_partial = metric_data([{"Name": "Service", "Value": "checkout"}])
    assert md_partial["Values"] == [], (
        f"GetMetricData with a partial dimension set must return no Values, got {md_partial['Values']}"
    )
    assert md_partial["StatusCode"] == "Complete", (
        f"a no-match dimension query is a successful empty result, not an error/partial one; "
        f"got StatusCode={md_partial['StatusCode']}"
    )

    # Control: the exact-match query still works after all the negatives.
    control = stats(full_dims)
    assert control and control[0]["Sum"] == 42.0, (
        f"the exact-dimension query must still return Sum=42.0 after the negatives, got {control}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
