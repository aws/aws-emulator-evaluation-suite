"""get-metric-data-metric-math-invalid-expression-rejected."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-data-metric-math-invalid-expression-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData rejects a malformed metric-math Expression with an exact ValidationError
    at request time rather than a 200 with a buried StatusCode; a plain query still succeeds."""
    cw = ctx.client("cloudwatch")
    end = dt.datetime.utcnow()
    start = end - dt.timedelta(hours=1)

    bad_query = [{"Id": "e1", "Expression": "SUM(", "ReturnData": True}]
    code, message = _error_code(
        lambda: cw.get_metric_data(MetricDataQueries=bad_query, StartTime=start, EndTime=end)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = "Error in expression 'e1': Invalid syntax"
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    good_query = [
        {
            "Id": "m1",
            "MetricStat": {
                "Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization"},
                "Period": 300,
                "Stat": "Average",
            },
            "ReturnData": True,
        }
    ]
    resp = cw.get_metric_data(MetricDataQueries=good_query, StartTime=start, EndTime=end)
    assert resp["MetricDataResults"][0]["Id"] == "m1"


def _error_code(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected GetMetricData to reject the malformed expression, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
