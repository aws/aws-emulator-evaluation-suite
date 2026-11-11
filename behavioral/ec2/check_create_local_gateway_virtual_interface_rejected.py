"""create-local-gateway-virtual-interface-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-local-gateway-virtual-interface-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_FAKE_GROUP_ID = "lgw-vif-grp-00000000000000000"
_FAKE_LAG_ID = "lag-00000000000000000"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With DescribeLocalGateways answering, CreateLocalGatewayVirtualInterface naming an unknown virtual interface
    group and LAG is refused with a NotFound code for the virtual interface group, and no virtual interface for
    that group exists.
    """
    ec2 = ctx.client("ec2")
    ec2.describe_local_gateways()

    code = _rejected(
        lambda: ec2.create_local_gateway_virtual_interface(
            LocalGatewayVirtualInterfaceGroupId=_FAKE_GROUP_ID,
            OutpostLagId=_FAKE_LAG_ID,
            LocalAddress="169.254.100.1",
            PeerAddress="169.254.100.2",
            PeerBgpAsn=65000,
            Vlan=100,
        )
    )
    assert code.endswith("NotFound"), f"expected a *.NotFound error code, got {code!r}"
    assert "localgatewayvirtualinterfacegroupid" in code.lower(), (
        f"expected the error to reference the local gateway virtual interface group, got {code!r}"
    )

    existing = ec2.describe_local_gateway_virtual_interfaces()["LocalGatewayVirtualInterfaces"]
    assert not any(v["LocalGatewayVirtualInterfaceGroupId"] == _FAKE_GROUP_ID for v in existing), (
        f"the rejected call still left a virtual interface wired to the nonexistent group "
        f"{_FAKE_GROUP_ID!r}: {existing!r}"
    )


def _rejected(fn):
    """Call fn(); return the ClientError code. An unexpected SUCCESS raises -- an emulator accepting
    hardware IDs real AWS refuses is the strongest signal available. A botocore ParamValidationError
    is deliberately left uncaught: it means the request never left the SDK, which is evidence about
    this check's own arguments, not about AWS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(
        f"expected CreateLocalGatewayVirtualInterface to fail for nonexistent hardware IDs, "
        f"got {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
