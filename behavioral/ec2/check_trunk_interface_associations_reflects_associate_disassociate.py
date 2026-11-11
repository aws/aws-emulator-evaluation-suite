"""trunk-interface-associations-reflects-associate-disassociate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trunk-interface-associations-reflects-associate-disassociate"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrunkInterfaceAssociations and AssociateTrunkInterface, for an account without ENI trunking,
    fail with OperationNotPermitted and the exact "is not permitted" message (not an IAM denial), and a
    second Describe after the failed Associate is refused identically."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.88.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.88.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    trunk = ec2.create_network_interface(SubnetId=subnet_id, InterfaceType="trunk")[
        "NetworkInterface"
    ]
    trunk_id = trunk["NetworkInterfaceId"]
    # The refusal names the caller's account, which the interface reports as its owner.
    not_permitted = f"User {trunk['OwnerId']} is not permitted to perform this operation"
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=trunk_id))
    assert trunk["InterfaceType"] == "trunk", (
        f"expected CreateNetworkInterface(InterfaceType=trunk) to honor the request, "
        f"got InterfaceType={trunk.get('InterfaceType')!r}"
    )

    branch = ec2.create_network_interface(SubnetId=subnet_id)["NetworkInterface"]
    branch_id = branch["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=branch_id))

    # Positive control, on a DIFFERENT (ungated) operation: an independent read of
    # both interfaces confirms the account/credentials are otherwise healthy for EC2
    # network-interface reads before we hit the entitlement-gated family below.
    described = {
        ni["NetworkInterfaceId"]: ni
        for ni in ec2.describe_network_interfaces(NetworkInterfaceIds=[trunk_id, branch_id])[
            "NetworkInterfaces"
        ]
    }
    assert described[trunk_id]["InterfaceType"] == "trunk", (
        f"independent read (DescribeNetworkInterfaces) disagrees with the create "
        f"response about the trunk interface's type: {described[trunk_id]!r}"
    )
    assert described[branch_id].get("InterfaceType", "interface") == "interface", (
        f"independent read (DescribeNetworkInterfaces) shows an unexpected type for "
        f"the plain branch interface: {described[branch_id]!r}"
    )

    try:
        ec2.describe_trunk_interface_associations()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "OperationNotPermitted", (
            f"expected DescribeTrunkInterfaceAssociations to be refused with the "
            f"ENI-trunking entitlement-gate code OperationNotPermitted, got "
            f"{code}: {message}"
        )
        assert message == not_permitted, (
            f"expected the entitlement-gate phrasing {not_permitted!r}; got: {message!r}"
        )
        assert "not authorized" not in message.lower(), (
            f"'not authorized' phrasing means an IAM AccessDenied/UnauthorizedOperation "
            f"refusal, not the entitlement gate this check asserts; got: {message!r}"
        )
    else:
        raise AssertionError(
            "DescribeTrunkInterfaceAssociations succeeded in this account -- the "
            "trunk-association API family is no longer entitlement-gated here, so "
            "the associate/disassociate lifecycle this check's name describes is "
            "reachable and this check needs to assert that lifecycle directly "
            "instead of the withdrawal contract asserted here."
        )

    try:
        assoc = ec2.associate_trunk_interface(
            BranchInterfaceId=branch_id, TrunkInterfaceId=trunk_id, VlanId=42
        )["InterfaceAssociation"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "OperationNotPermitted", (
            f"expected AssociateTrunkInterface to be refused with the ENI-trunking "
            f"entitlement-gate code OperationNotPermitted, got {code}: {message}"
        )
        assert message == not_permitted, (
            f"expected the entitlement-gate phrasing {not_permitted!r}; got: {message!r}"
        )
    else:
        association_id = assoc["AssociationId"]
        ctx.on_cleanup(lambda: ec2.disassociate_trunk_interface(AssociationId=association_id))
        raise AssertionError(
            "AssociateTrunkInterface succeeded in this account -- ENI trunking is "
            "no longer entitlement-gated here, so the associate/disassociate "
            "lifecycle this check's name describes is reachable and this check "
            "needs to assert that lifecycle directly instead of the withdrawal "
            "contract asserted here."
        )

    # The refusal is stable: trying (and failing) to associate did not change the
    # account's relationship to the API -- a second Describe attempt is refused the
    # same way, not e.g. now succeeding empty or erroring differently.
    try:
        ec2.describe_trunk_interface_associations()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "OperationNotPermitted", (
            f"expected the post-Associate-attempt DescribeTrunkInterfaceAssociations "
            f"to still be refused with OperationNotPermitted, got {code}: {message}"
        )
        assert message == not_permitted, f"unexpected message: {message!r}"
    else:
        raise AssertionError(
            "DescribeTrunkInterfaceAssociations succeeded on retry after having just "
            "been refused -- the entitlement gate is not stable across the run."
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
