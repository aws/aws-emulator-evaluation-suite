"""op-contract-get-aws-network-performance-data."""
from __future__ import annotations

import datetime
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-aws-network-performance-data"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# The exact message EC2 returns for every DryRun call the caller is authorised for.
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAwsNetworkPerformanceData returns a real Infrastructure Performance
    (inter-Region aggregate latency) time series matched by query Id, and honors the
    DryRun permission-check contract."""
    ec2 = ctx.client("ec2")

    # us-east-1/us-west-2 is a heavily-trafficked pair with pre-published aggregate-latency
    # data (no EnableAwsNetworkPerformanceMetricSubscription needed), so pick whichever of the
    # two isn't ctx.region for a query that is reliably backed by real MetricPoints.
    other_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    end = datetime.datetime.utcnow().replace(microsecond=0)
    start = end - datetime.timedelta(hours=6)

    query = {
        "Source": ctx.region,
        "Destination": other_region,
        "Metric": "aggregate-latency",
        "Statistic": "p50",
        "Period": "five-minutes",
    }

    # --- success path: a matching DataResponse is returned for the submitted query,
    # echoing the query's own scoping fields, and carrying a real published time series
    # (us-east-1/us-west-2 aggregate-latency is populated without a subscription) ---
    resp = ec2.get_aws_network_performance_data(
        DataQueries=[{**query, "Id": "q1"}], StartTime=start, EndTime=end
    )
    responses = resp["DataResponses"]
    assert len(responses) == 1, f"expected exactly 1 DataResponse, got {responses!r}"
    response = responses[0]
    assert response["Id"] == "q1", f"expected Id 'q1', got {response.get('Id')!r}"
    for field, expected in query.items():
        assert response.get(field) == expected, (
            f"DataResponse.{field} = {response.get(field)!r}, expected {expected!r}"
        )

    points = response.get("MetricPoints") or []
    assert points, f"expected at least one MetricPoint for {ctx.region}->{other_region}, got none"
    period = datetime.timedelta(minutes=5)
    prev_end = None
    for point in points:
        assert isinstance(point["Value"], (int, float)), f"non-numeric MetricPoint value {point!r}"
        assert point["StartDate"] < point["EndDate"], f"MetricPoint start >= end: {point!r}"
        assert point["EndDate"] - point["StartDate"] == period, (
            f"MetricPoint span != five-minutes: {point!r}"
        )
        if prev_end is not None:
            assert point["StartDate"] == prev_end, (
                f"MetricPoints not contiguous/ascending: {prev_end} then {point['StartDate']!r}"
            )
        prev_end = point["EndDate"]

    # --- error boundary: DryRun permission-check contract ---
    code, message = _error(lambda: ec2.get_aws_network_performance_data(
        DataQueries=[{**query, "Id": "q1"}], StartTime=start, EndTime=end, DryRun=True
    ))
    assert code == "DryRunOperation", code
    assert message == _DRY_RUN_MESSAGE, message


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
