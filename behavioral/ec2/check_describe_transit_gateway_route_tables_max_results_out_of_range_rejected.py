"""describe-transit-gateway-route-tables-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-transit-gateway-route-tables-max-results-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGatewayRouteTables accepts MaxResults=5 and rejects
    MaxResults=100000, above the documented maximum of 1000, with InvalidParameterValue
    and its exact message.
    """
    ec2 = ctx.client("ec2")

    resp = ec2.describe_transit_gateway_route_tables(MaxResults=5)
    assert "TransitGatewayRouteTables" in resp, sorted(resp)
    assert isinstance(resp["TransitGatewayRouteTables"], list)

    code, message = _error(
        lambda: ec2.describe_transit_gateway_route_tables(MaxResults=100000)
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue for MaxResults=100000 (above documented "
        f"maximum of 1000), got {code!r}"
    )
    expected = "Value (100000) for parameter MaxResults is invalid. "
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
