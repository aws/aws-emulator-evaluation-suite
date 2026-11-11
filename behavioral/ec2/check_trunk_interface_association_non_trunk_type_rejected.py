"""trunk-interface-association-non-trunk-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trunk-interface-association-non-trunk-type-rejected"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateTrunkInterface, for an account without ENI trunking, fails with OperationNotPermitted and
    an identical "is not permitted" message for a non-trunk and a real trunk TrunkInterfaceId and creates
    no association; DescribeTrunkInterfaceAssociations is refused the same way."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-trunk-")

    def _tag_spec(resource_type: str, suffix: str):
        return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": f"{name}-{suffix}"}]}]

    vpc_id = ec2.create_vpc(CidrBlock="10.89.0.0/16", TagSpecifications=_tag_spec("vpc", "vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.89.1.0/24", TagSpecifications=_tag_spec("subnet", "subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    not_a_trunk_id = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=_tag_spec("network-interface", "not-trunk")
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=not_a_trunk_id))
    real_trunk_id = ec2.create_network_interface(
        SubnetId=subnet_id, InterfaceType="trunk", TagSpecifications=_tag_spec("network-interface", "real-trunk")
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=real_trunk_id))
    branch_id = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=_tag_spec("network-interface", "branch")
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=branch_id))

    # Positive control, on a DIFFERENT (ungated) operation: an independent read
    # confirms the account/credentials are otherwise healthy for EC2 before we
    # hit the entitlement-gated AssociateTrunkInterface family below.
    described = {
        ni["NetworkInterfaceId"]: ni
        for ni in ec2.describe_network_interfaces(
            NetworkInterfaceIds=[not_a_trunk_id, real_trunk_id, branch_id]
        )["NetworkInterfaces"]
    }
    assert described[real_trunk_id]["InterfaceType"] == "trunk", (
        f"independent read (DescribeNetworkInterfaces) disagrees with the create "
        f"response about the trunk interface's type: {described[real_trunk_id]!r}"
    )
    assert described[not_a_trunk_id].get("InterfaceType", "interface") == "interface", (
        f"independent read (DescribeNetworkInterfaces) shows an unexpected type for "
        f"the plain (non-trunk) interface: {described[not_a_trunk_id]!r}"
    )

    invalid_code, invalid_message = _associate_error(ec2, branch_id, not_a_trunk_id)
    valid_code, valid_message = _associate_error(ec2, branch_id, real_trunk_id)

    assert invalid_code == "OperationNotPermitted", (
        f"expected the non-trunk TrunkInterfaceId call to be refused with the "
        f"ENI-trunking entitlement-gate code OperationNotPermitted, got "
        f"{invalid_code}: {invalid_message}"
    )
    expected_message = f"User {ctx.account} is not permitted to perform this operation"
    assert invalid_message == expected_message, (
        f"expected the entitlement-gate message {expected_message!r}, distinct from an "
        f"IAM AccessDenied/UnauthorizedOperation refusal; got: {invalid_message!r}"
    )

    assert valid_code == "OperationNotPermitted", (
        f"expected the call against a REAL trunk TrunkInterfaceId to be refused "
        f"identically to the non-trunk one (proving the entitlement gate fires "
        f"before any TrunkInterfaceId type validation), got {valid_code}: {valid_message}"
    )
    assert valid_message == invalid_message, (
        f"expected the valid- and invalid-TrunkInterfaceId calls to be refused with "
        f"the IDENTICAL message (proving the gate does not discriminate on "
        f"TrunkInterfaceId validity), got:\n  invalid: {invalid_message!r}\n"
        f"  valid:   {valid_message!r}"
    )

    # Effect absent either way: no association was created for the branch interface.
    # DescribeTrunkInterfaceAssociations is gated by the same entitlement boundary,
    # so being refused there too is itself the honest, independently-observed
    # confirmation -- not silence about whether an association exists.
    try:
        resp = ec2.describe_trunk_interface_associations()
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "OperationNotPermitted", (
            f"expected DescribeTrunkInterfaceAssociations to be refused with the "
            f"same entitlement-gate code as Associate, got "
            f"{exc.response['Error']['Code']}: {exc.response['Error'].get('Message', '')}"
        )
        describe_message = exc.response["Error"].get("Message")
        expected_describe = f"User {ctx.account} is not permitted to perform this operation"
        assert describe_message == expected_describe, (
            f"expected message {expected_describe!r}, got {describe_message!r}"
        )
    else:
        assert not any(a["BranchInterfaceId"] == branch_id for a in resp["InterfaceAssociations"]), (
            f"branch interface {branch_id} unexpectedly appears in "
            f"DescribeTrunkInterfaceAssociations after two refused Associate calls"
        )


def _associate_error(ec2, branch_id: str, trunk_id: str):
    """(code, message) of the refused AssociateTrunkInterface; an unexpected success raises."""
    try:
        result = ec2.associate_trunk_interface(BranchInterfaceId=branch_id, TrunkInterfaceId=trunk_id, VlanId=7)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"AssociateTrunkInterface with TrunkInterfaceId {trunk_id!r} was expected to be refused "
        f"by the ENI-trunking entitlement gate, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
