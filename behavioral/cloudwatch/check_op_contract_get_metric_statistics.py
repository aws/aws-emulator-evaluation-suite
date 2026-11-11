"""op-contract-getMetricStatistics."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "op-contract-getMetricStatistics"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics aggregates PutMetricData points into the requested Statistics
    (Sum matches the published value) over the given Period; omitting both Statistics and
    ExtendedStatistics is rejected with InvalidParameterCombination."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-ns-")
    metric_name = "BytesProcessed"
    now = datetime.now(timezone.utc)

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": now, "Value": 17.0, "Unit": "Bytes"}],
    )

    datapoints = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=5),
            EndTime=now + timedelta(minutes=5),
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"],
        lambda dps: len(dps) > 0,
        timeout_s=90,
        interval_s=5,
    )
    assert datapoints[0]["Sum"] == 17.0, f"expected Sum 17.0, got {datapoints[0]['Sum']}"
    assert datapoints[0]["SampleCount"] == 1.0, (
        f"expected SampleCount 1.0, got {datapoints[0]['SampleCount']}"
    )
    assert datapoints[0]["Unit"] == "Bytes", f"expected Unit Bytes, got {datapoints[0]['Unit']}"

    code, message = _error(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(minutes=5),
            EndTime=now,
            Period=60,
        )
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination when neither Statistics nor ExtendedStatistics "
        f"is given, got {code}"
    )
    expected = "At least one of the parameters Statistics and ExtendedStatistics must be specified."
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
