"""get-metric-data-invalid-next-token-rejected."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-data-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData with a corrupted NextToken raises InvalidNextToken instead of
    silently resetting pagination and returning a first page."""
    cw = ctx.client("cloudwatch")
    now = dt.datetime.utcnow()

    query = {
        "Id": "m1",
        "MetricStat": {
            "Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization"},
            "Period": 300,
            "Stat": "Average",
        },
    }

    # Positive control: the identical query with no NextToken succeeds, so the
    # rejection below is specific to the corrupted token, not to this query shape
    # or account permissions.
    control = cw.get_metric_data(
        MetricDataQueries=[query],
        StartTime=now - dt.timedelta(hours=3),
        EndTime=now,
    )
    assert "MetricDataResults" in control, (
        f"expected a normal GetMetricData call to succeed, got {control!r}"
    )

    code, message = _reject(
        lambda: cw.get_metric_data(
            MetricDataQueries=[query],
            StartTime=now - dt.timedelta(hours=3),
            EndTime=now,
            NextToken="this-is-not-a-real-next-token-!!garbled==",
        )
    )
    assert code == "InvalidNextToken", code
    # AWS returns this code with no message text.
    assert message == "", f"expected an empty message, got {message!r}"


def _reject(fn):
    """Call fn(); return the botocore Error (Code, Message) if a ClientError is raised. An
    unexpected SUCCESS raises with the actual response."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected GetMetricData to reject a garbled NextToken, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
