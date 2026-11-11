"""op-contract-getMetricStatistics-dup."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "op-contract-getMetricStatistics-dup"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics returns the published StatisticValues (Sum 50.0, SampleCount 5), and a 90-day
    range at Period=60 (over the 1,440-datapoint limit) raises InvalidParameterCombination with the
    exact message naming the requested datapoint count."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cw-ns-")
    metric_name = "QueueDepth"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ts = now - timedelta(seconds=30)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": ts,
                "StatisticValues": {"SampleCount": 5, "Sum": 50.0, "Minimum": 10.0, "Maximum": 10.0},
                "Unit": "Count",
            }
        ],
    )

    def _fetch():
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=1),
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )

    result = _poll_until(_fetch, lambda r: bool(r["Datapoints"]), timeout_s=90.0)
    datapoint = result["Datapoints"][0]
    assert datapoint["Sum"] == 50.0, f"expected Sum 50.0, got {datapoint['Sum']}"
    assert datapoint["SampleCount"] == 5.0, f"expected SampleCount 5.0, got {datapoint['SampleCount']}"

    # error boundary: a 90-day range at a 60-second period asks for far more than
    # the 1,440-datapoint maximum CloudWatch allows in a single call.
    start = now - timedelta(days=90)
    code, message = _error(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=now,
            Period=60,
            Statistics=["Sum"],
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    requested = int((now - start).total_seconds()) // 60
    expected = (
        f"You have requested up to {requested} datapoints, which exceeds the limit of 1440. "
        "You may reduce the datapoints requested by increasing Period, or decreasing the time range."
    )
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"


def _poll_until(probe, predicate, timeout_s: float = 30.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
