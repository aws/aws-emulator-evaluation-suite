"""op-contract-describe-local-gateway-virtual-interfaces-superseded-stub."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-local-gateway-virtual-interfaces-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLocalGatewayVirtualInterfaces answers 200 with a list of rows with IDs, an unknown interface
    ID returns an empty list, and DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_local_gateway_virtual_interfaces()
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert "LocalGatewayVirtualInterfaces" in resp, f"missing key: {sorted(resp)}"
    interfaces = resp["LocalGatewayVirtualInterfaces"]
    assert isinstance(interfaces, list), f"expected a list, got {type(interfaces)!r}"
    for vif in interfaces:
        assert "LocalGatewayVirtualInterfaceId" in vif, f"missing LocalGatewayVirtualInterfaceId: {sorted(vif)}"
        assert "LocalGatewayId" in vif, f"missing LocalGatewayId: {sorted(vif)}"

    # A well-formed but nonexistent id is a plain filter here (not an
    # existence lookup): it narrows the result to empty, not an error.
    resp2 = ec2.describe_local_gateway_virtual_interfaces(
        LocalGatewayVirtualInterfaceIds=["lgw-vif-00000000000000000"]
    )
    assert resp2["LocalGatewayVirtualInterfaces"] == [], (
        f"expected empty, got {resp2['LocalGatewayVirtualInterfaces']}"
    )

    code, message = _client_error(lambda: ec2.describe_local_gateway_virtual_interfaces(DryRun=True))
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
