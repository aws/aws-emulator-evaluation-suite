"""op-contract-describe-local-gateway-virtual-interface-groups."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-local-gateway-virtual-interface-groups"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLocalGatewayVirtualInterfaceGroups: success-path shape + DryRun boundary.

    Only populated for accounts with Outposts-attached Local Gateways; on a plain
    account the contract under test is the response shape and DryRun semantics.
    """
    ec2 = ctx.client("ec2")

    resp = ec2.describe_local_gateway_virtual_interface_groups()
    assert "LocalGatewayVirtualInterfaceGroups" in resp, f"missing key: {sorted(resp)}"
    groups = resp["LocalGatewayVirtualInterfaceGroups"]
    assert isinstance(groups, list), f"expected a list, got {groups!r}"
    for group in groups:
        assert "LocalGatewayVirtualInterfaceGroupId" in group, (
            f"group missing LocalGatewayVirtualInterfaceGroupId: {sorted(group)}"
        )
        assert "LocalGatewayId" in group, f"group missing LocalGatewayId: {sorted(group)}"

    # Filtering by a well-formed but nonexistent id narrows to empty, not an error.
    resp2 = ec2.describe_local_gateway_virtual_interface_groups(
        LocalGatewayVirtualInterfaceGroupIds=["lgw-vif-grp-00000000000000000"]
    )
    assert resp2["LocalGatewayVirtualInterfaceGroups"] == [], (
        f"expected empty on nonexistent id filter, got {resp2['LocalGatewayVirtualInterfaceGroups']!r}"
    )

    # Error boundary: DryRun.
    code, message = _client_error(
        lambda: ec2.describe_local_gateway_virtual_interface_groups(DryRun=True)
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
