"""get-metric-statistics-invalid-period-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "get-metric-statistics-invalid-period-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics rejects a Period that is not a multiple of 60 seconds."""
    cw = ctx.client("cloudwatch")
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=1)

    def _call(period):
        return cw.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            StartTime=start,
            EndTime=end,
            Period=period,
            Statistics=["Average"],
        )

    # Positive control: the identical call shape with a valid Period succeeds, so the
    # rejection below is attributable to Period=61 and not to anything else about the
    # request (credentials, namespace, time window).
    control = _call(60)
    assert "Datapoints" in control, (
        f"positive control (Period=60) did not return a Datapoints field: {control!r}"
    )

    code, message = _error_code(lambda: _call(61))
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for Period=61, got {code}"
    )
    expected = "The parameter Period must be a multiple of 60."
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects Period=61, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
