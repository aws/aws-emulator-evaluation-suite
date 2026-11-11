"""op-contract-describeTransitGatewayRouteTableAnnouncements."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeTransitGatewayRouteTableAnnouncements"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTransitGatewayRouteTableAnnouncements returns a well-shaped collection on
    the success path and honors the documented DryRun contract as its error boundary."""
    ec2 = ctx.client("ec2")
    op_name = "describe_transit_gateway_route_table_announcements"
    if not hasattr(ec2, op_name):
        raise AssertionError(f"{op_name} not available in installed botocore/EC2 model")

    resp = ec2.describe_transit_gateway_route_table_announcements()
    assert "TransitGatewayRouteTableAnnouncements" in resp, (
        f"missing TransitGatewayRouteTableAnnouncements field in response: {sorted(resp)}"
    )
    items = resp["TransitGatewayRouteTableAnnouncements"]
    assert isinstance(items, list), f"expected a list, got {type(items).__name__}: {items!r}"

    # Filters-based lookup on a bogus (but well-formed) transit-gateway-id must
    # deterministically return an empty collection rather than error, mirroring the
    # equivalent boundary on DescribeTransitGatewayRouteTables.
    resp_filtered = ec2.describe_transit_gateway_route_table_announcements(
        Filters=[{"Name": "transit-gateway-id", "Values": ["tgw-00000000000000000"]}]
    )
    filtered_items = resp_filtered["TransitGatewayRouteTableAnnouncements"]
    assert filtered_items == [], f"expected empty filtered result, got {filtered_items}"

    code, code_message = _error_code(lambda: ec2.describe_transit_gateway_route_table_announcements(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
