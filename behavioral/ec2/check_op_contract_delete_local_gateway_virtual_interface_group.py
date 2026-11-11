"""op-contract-delete-local-gateway-virtual-interface-group."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-local-gateway-virtual-interface-group"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLocalGatewayVirtualInterfaceGroup with DryRun answers DryRunOperation and leaves an existing
    Outposts group in place; without one, a never-allocated ID answers DryRunOperation with DryRun and
    InvalidLocalGatewayVirtualInterfaceGroupID.NotFound without (exact messages)."""
    ec2 = ctx.client("ec2")

    vif_groups = ec2.describe_local_gateway_virtual_interface_groups().get(
        "LocalGatewayVirtualInterfaceGroups", []
    )

    if vif_groups:
        vif_group_id = vif_groups[0]["LocalGatewayVirtualInterfaceGroupId"]

        # error boundary: DryRun must short-circuit with DryRunOperation and must NOT mutate
        # the real, physically-provisioned interface group.
        code, message = _error(
            lambda: ec2.delete_local_gateway_virtual_interface_group(
                LocalGatewayVirtualInterfaceGroupId=vif_group_id, DryRun=True
            )
        )
        assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
        assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"

        still_there = ec2.describe_local_gateway_virtual_interface_groups(
            LocalGatewayVirtualInterfaceGroupIds=[vif_group_id]
        )["LocalGatewayVirtualInterfaceGroups"]
        assert (
            len(still_there) == 1
            and still_there[0]["LocalGatewayVirtualInterfaceGroupId"] == vif_group_id
        ), "DryRun must not delete the real virtual interface group"
        return

    fake_id = "lgw-vif-grp-0123456789abcdef0"

    dryrun_code, dryrun_message = _error(
        lambda: ec2.delete_local_gateway_virtual_interface_group(
            LocalGatewayVirtualInterfaceGroupId=fake_id, DryRun=True
        )
    )
    assert dryrun_code == "DryRunOperation", (
        "expected DryRunOperation (permission-check must precede existence-check), "
        f"got {dryrun_code}"
    )
    assert dryrun_message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {dryrun_message!r}"

    real_code, real_message = _error(
        lambda: ec2.delete_local_gateway_virtual_interface_group(
            LocalGatewayVirtualInterfaceGroupId=fake_id, DryRun=False
        )
    )
    assert real_code == "InvalidLocalGatewayVirtualInterfaceGroupID.NotFound", f"unexpected code {real_code}"
    assert real_message == f"The local-gateway-virtual-interface-group ID '{fake_id}' does not exist", f"unexpected message {real_message!r}"

    all_group_ids = {
        g["LocalGatewayVirtualInterfaceGroupId"]
        for g in ec2.describe_local_gateway_virtual_interface_groups().get(
            "LocalGatewayVirtualInterfaceGroups", []
        )
    }
    assert fake_id not in all_group_ids, (
        "the fabricated id must not exist as a real resource, or the NotFound above would "
        "be meaningless"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
