"""get-metric-statistics-missing-statistic-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-statistics-missing-statistic-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics requires Statistics or ExtendedStatistics; omitting both is rejected, no partial data returned."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real-CW-")
    metric_name = "MissingStatMetric"
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ts = now - timedelta(minutes=5)
    start = now - timedelta(minutes=10)
    end = now

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Timestamp": ts, "Value": 12.0}],
    )

    code, message = _error_code(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    expected = "At least one of the parameters Statistics and ExtendedStatistics must be specified."
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    # Positive control: the identical call with Statistics supplied succeeds and eventually
    # surfaces the published datapoint, proving the rejection above isn't a blanket failure
    # (an empty-Datapoints response alone can't distinguish "rejects only the omission" from
    # "never returns any data").
    points = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start,
            EndTime=end,
            Period=60,
            Statistics=["Average"],
        )["Datapoints"],
        lambda pts: len(pts) > 0,
        timeout_s=60,
        interval_s=3,
    )
    assert any(abs(p["Average"] - 12.0) < 0.01 for p in points), (
        f"expected a datapoint averaging 12.0, got {points!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
