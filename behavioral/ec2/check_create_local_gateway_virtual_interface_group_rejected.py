"""create-local-gateway-virtual-interface-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-local-gateway-virtual-interface-group-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With DescribeLocalGateways answering, CreateLocalGatewayVirtualInterfaceGroup on an unknown LocalGatewayId is
    refused with InvalidLocalGatewayID.NotFound and its exact message; the success path needs an Outpost.
    """
    ec2 = ctx.client("ec2")

    control = ec2.describe_local_gateways()
    assert "LocalGateways" in control, (
        f"expected DescribeLocalGateways to answer with a LocalGateways list, got keys {sorted(control)!r}"
    )

    code, message = _client_error(
        lambda: ec2.create_local_gateway_virtual_interface_group(
            LocalGatewayId="lgw-00000000000000000",
        )
    )
    assert code == "InvalidLocalGatewayID.NotFound", f"expected InvalidLocalGatewayID.NotFound, got {code!r}"
    expected_message = "The local-gateway ID 'lgw-00000000000000000' does not exist"
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
