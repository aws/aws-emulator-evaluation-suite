"""get-metric-statistics-and-toomany-datapoints-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-statistics-and-toomany-datapoints-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics returns the exact published Sum/SampleCount, and rejects a request
    exceeding the 1,440-datapoint maximum with an exact InvalidParameterCombination."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
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

    # 90 days at a 60 s period is 129,600 datapoints; the range/period pairing is what is
    # invalid, so the error is InvalidParameterCombination rather than InvalidParameterValue.
    code, message = _error_code(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(days=90),
            EndTime=now,
            Period=60,
            Statistics=["Sum"],
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    expected = (
        "You have requested up to 129600 datapoints, which exceeds the limit of 1440. "
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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
