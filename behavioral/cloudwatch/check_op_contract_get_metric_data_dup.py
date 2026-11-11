"""op-contract-getMetricData-dup."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "op-contract-getMetricData-dup"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData round-trips a PutMetricData statistic set (Sum over a known
    SampleCount) with StatusCode Complete, and is rejected with InvalidNextToken
    for a garbage pagination token."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cw-ns-")
    metric_name = "RequestLatency"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ts = now - timedelta(seconds=30)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric_name,
                "Timestamp": ts,
                "StatisticValues": {"SampleCount": 5, "Sum": 50.0, "Minimum": 10.0, "Maximum": 10.0},
                "Unit": "Milliseconds",
            }
        ],
    )

    def _fetch():
        return cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {"Namespace": namespace, "MetricName": metric_name},
                        "Period": 60,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            ],
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=1),
        )

    result = _poll_until(_fetch, lambda r: bool(r["MetricDataResults"][0]["Values"]), timeout_s=90.0)
    metric_result = result["MetricDataResults"][0]
    assert metric_result["StatusCode"] == "Complete", (
        f"expected StatusCode Complete, got {metric_result['StatusCode']!r}"
    )
    assert metric_result["Values"][0] == 50.0, f"expected Sum 50.0, got {metric_result['Values']}"

    # error boundary: a stale/garbage NextToken is rejected outright.
    code, message = _error(
        lambda: cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "m1",
                    "MetricStat": {
                        "Metric": {"Namespace": namespace, "MetricName": metric_name},
                        "Period": 60,
                        "Stat": "Sum",
                    },
                }
            ],
            StartTime=now - timedelta(minutes=5),
            EndTime=now,
            NextToken="garbage-not-a-real-token",
        )
    )
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code!r}"
    # real AWS sends this refusal with an empty message
    assert message == "", f"expected an empty refusal message, got {message!r}"


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
