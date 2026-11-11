"""associate-trunk-interface-non-trunk-eni-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "associate-trunk-interface-non-trunk-eni-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateTrunkInterface answers DryRunOperation under DryRun but is refused with OperationNotPermitted and
    its exact message for both a non-trunk and a trunk-type ENI, as is DescribeTrunkInterfaceAssociations:
    customer accounts cannot use ENI trunking.
    """
    ec2 = ctx.client("ec2")
    tag_spec = lambda rt, name: [  # noqa: E731
        {"ResourceType": rt, "Tags": [{"Key": "Name", "Value": name}]}
    ]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=tag_spec("vpc", ctx.unique_name("sim2real-trunk-eni-")),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.90.1.0/24",
        TagSpecifications=tag_spec("subnet", ctx.unique_name("sim2real-trunk-eni-")),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    not_a_trunk_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=tag_spec("network-interface", ctx.unique_name("sim2real-not-trunk-")),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=not_a_trunk_id))
    real_trunk_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        InterfaceType="trunk",
        TagSpecifications=tag_spec("network-interface", ctx.unique_name("sim2real-trunk-")),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=real_trunk_id))
    branch_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=tag_spec("network-interface", ctx.unique_name("sim2real-branch-")),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=branch_id))

    # Positive control: DryRun on the exact call proves the account, credentials and request
    # shape are otherwise accepted -- the operation is reachable, just refused for real.
    dry_run_code, dry_run_code_message = _error_code(
        lambda: ec2.associate_trunk_interface(
            BranchInterfaceId=branch_id, TrunkInterfaceId=not_a_trunk_id, VlanId=11, DryRun=True
        )
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    expected_dry_run_code_message = "Request would have succeeded, but DryRun flag is set."
    assert dry_run_code_message == expected_dry_run_code_message, f"expected message {expected_dry_run_code_message!r}, got {dry_run_code_message!r}"

    # The withdrawal, against the non-trunk ENI this check names in its id.
    code_non_trunk, code_non_trunk_message = _error_code(
        lambda: ec2.associate_trunk_interface(
            BranchInterfaceId=branch_id, TrunkInterfaceId=not_a_trunk_id, VlanId=11
        )
    )
    assert code_non_trunk == "OperationNotPermitted", (
        f"expected OperationNotPermitted, got {code_non_trunk!r}"
    )
    expected_code_non_trunk_message = f"User {ctx.account} is not permitted to perform this operation"
    assert code_non_trunk_message == expected_code_non_trunk_message, f"expected message {expected_code_non_trunk_message!r}, got {code_non_trunk_message!r}"

    # The same refusal for a real trunk-type ENI: the gate is on the operation, so accepting the call or
    # answering another code (e.g. InvalidParameterValue) differs from AWS.
    code_real_trunk, code_real_trunk_message = _error_code(
        lambda: ec2.associate_trunk_interface(
            BranchInterfaceId=branch_id, TrunkInterfaceId=real_trunk_id, VlanId=11
        )
    )
    assert code_real_trunk == "OperationNotPermitted", (
        f"expected OperationNotPermitted, got {code_real_trunk!r}"
    )
    expected_code_real_trunk_message = f"User {ctx.account} is not permitted to perform this operation"
    assert code_real_trunk_message == expected_code_real_trunk_message, f"expected message {expected_code_real_trunk_message!r}, got {code_real_trunk_message!r}"

    # Terminal independent read, through a different operation than the mutating calls above:
    # DescribeTrunkInterfaceAssociations is refused with the same specific code, so this
    # principal has no reader through which an association could ever be observed to exist.
    describe_code, describe_code_message = _error_code(lambda: ec2.describe_trunk_interface_associations())
    assert describe_code == "OperationNotPermitted", (
        f"expected OperationNotPermitted, got {describe_code!r}"
    )
    expected_describe_code_message = f"User {ctx.account} is not permitted to perform this operation"
    assert describe_code_message == expected_describe_code_message, f"expected message {expected_describe_code_message!r}, got {describe_code_message!r}"


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
