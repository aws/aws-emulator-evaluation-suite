"""op-contract-describe-local-gateway-route-tables."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-local-gateway-route-tables"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLocalGatewayRouteTables answers with a list whose entries carry route table and local
    gateway IDs, a filter matching nothing returns an empty list, and DryRun answers DryRunOperation
    with its exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_local_gateway_route_tables()
    assert "LocalGatewayRouteTables" in resp, f"missing key in response: {sorted(resp)}"
    tables = resp["LocalGatewayRouteTables"]
    assert isinstance(tables, list), f"expected a list, got {type(tables)!r}"
    for table in tables:
        assert "LocalGatewayRouteTableId" in table, f"missing LocalGatewayRouteTableId: {sorted(table)}"
        assert "LocalGatewayId" in table, f"missing LocalGatewayId: {sorted(table)}"

    # Filtering by a well-formed but nonexistent id narrows to empty, not an error.
    resp2 = ec2.describe_local_gateway_route_tables(
        LocalGatewayRouteTableIds=["lgw-rtb-00000000000000000"]
    )
    assert resp2["LocalGatewayRouteTables"] == [], (
        f"expected empty, got {resp2['LocalGatewayRouteTables']}"
    )

    # Error boundary: DryRun.
    code, message = _client_error(lambda: ec2.describe_local_gateway_route_tables(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"expected {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
