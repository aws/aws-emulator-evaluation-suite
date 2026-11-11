"""create-local-gateway-route-rejected-unknown-route-table."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-local-gateway-route-rejected-unknown-route-table"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLocalGatewayRoute on an unknown route table id is refused with InvalidLocalGatewayRouteTableID.NotFound
    "The LocalGateway Route Table ID '<id>' does not exist"; the success path needs an Outpost.
    """
    ec2 = ctx.client("ec2")
    code, message = _client_error(
        lambda: ec2.create_local_gateway_route(
            LocalGatewayRouteTableId="lgw-rtb-00000000000000000",
            DestinationCidrBlock="192.0.2.0/24",
            LocalGatewayVirtualInterfaceGroupId="lgw-vif-grp-00000000000000000",
        )
    )
    assert code == "InvalidLocalGatewayRouteTableID.NotFound", (
        f"expected InvalidLocalGatewayRouteTableID.NotFound, got {code!r}"
    )
    expected_message = "The LocalGateway Route Table ID 'lgw-rtb-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call *fn*; return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
