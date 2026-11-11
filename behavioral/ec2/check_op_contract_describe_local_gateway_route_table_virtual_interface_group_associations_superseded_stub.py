"""op-contract-describe-local-gateway-route-table-virtual-interface-group-associations-superseded-stub."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-local-gateway-route-table-virtual-interface-group-associations-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations answers with a list of well-formed
    rows, an unknown association ID returns an empty list, and DryRun answers DryRunOperation with its
    exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_local_gateway_route_table_virtual_interface_group_associations()
    key = "LocalGatewayRouteTableVirtualInterfaceGroupAssociations"
    assert key in resp, f"missing key in response: {sorted(resp)}"
    rows = resp[key]
    # Every listed row must carry an association ID with the expected prefix and a parent route table
    # ID, not empty placeholders.
    assert isinstance(rows, list)
    for row in rows:
        assoc_id = row.get("LocalGatewayRouteTableVirtualInterfaceGroupAssociationId")
        rtb_id = row.get("LocalGatewayRouteTableId")
        assert assoc_id and assoc_id.startswith("lgw-vif-grp-assoc-"), f"bad association id: {row}"
        assert rtb_id and rtb_id.startswith("lgw-rtb-"), f"bad route table id: {row}"
        assert row.get("LocalGatewayId", "").startswith("lgw-"), f"bad local gateway id: {row}"

    # The ID parameter is a filter here, not an existence lookup: a well-formed nonexistent association
    # ID returns an empty result instead of raising NotFound.
    resp2 = ec2.describe_local_gateway_route_table_virtual_interface_group_associations(
        LocalGatewayRouteTableVirtualInterfaceGroupAssociationIds=[
            "lgw-vif-grp-assoc-00000000000000000"
        ]
    )
    assert resp2[key] == [], f"expected an empty narrowed result, got {resp2[key]}"

    code, message = _client_error(
        lambda: ec2.describe_local_gateway_route_table_virtual_interface_group_associations(DryRun=True)
    )
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
