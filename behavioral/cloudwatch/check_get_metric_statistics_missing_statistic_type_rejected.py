"""get-metric-statistics-missing-statistic-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-metric-statistics-missing-statistic-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics with neither Statistics nor ExtendedStatistics is rejected with an
    exact InvalidParameterCombination; the same call with Statistics returns the published value."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2Real/MissingStatCheck-")
    metric_name = "MissingStatMetric"
    now = time.time()

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 7.0, "Timestamp": now}],
    )

    kwargs = dict(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=now - 300,
        EndTime=now + 60,
        Period=60,
    )

    code, message = _error_code(lambda: cw.get_metric_statistics(**kwargs))
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code}"
    expected = "At least one of the parameters Statistics and ExtendedStatistics must be specified."
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    datapoints = _poll_datapoints(cw, namespace, metric_name, now, timeout_s=120.0)
    assert datapoints, "valid GetMetricStatistics call never returned the recorded datapoint"
    assert any(abs(p["Sum"] - 7.0) < 0.01 for p in datapoints), (
        f"expected a datapoint with Sum==7.0, got {datapoints}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_datapoints(cw, namespace, metric_name, around_ts, timeout_s, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        points = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=around_ts - 300,
            EndTime=around_ts + 300,
            Period=60,
            Statistics=["Sum"],
        )["Datapoints"]
        if points:
            return points
        time.sleep(interval_s)
    raise AssertionError(f"no datapoints for {metric_name!r} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
