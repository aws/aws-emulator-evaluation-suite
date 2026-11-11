"""create-local-gateway-route-table-rejected-unknown-gateway."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-local-gateway-route-table-rejected-unknown-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLocalGatewayRouteTable with an unknown LocalGatewayId is rejected with InvalidLocalGatewayID.NotFound
    "The LocalGateway ID '<id>' does not exist"; the success path needs an Outpost's local gateway."""
    ec2 = ctx.client("ec2")
    gateway_id = "lgw-00000000000000000"
    code, message = _error(
        lambda: ec2.create_local_gateway_route_table(
            LocalGatewayId=gateway_id,
        )
    )
    assert code == "InvalidLocalGatewayID.NotFound", (
        f"expected InvalidLocalGatewayID.NotFound for a nonexistent local gateway, got {code!r}"
    )
    expected = f"The LocalGateway ID '{gateway_id}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"expected CreateLocalGatewayRouteTable to reject a nonexistent LocalGatewayId, "
        f"but it succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
