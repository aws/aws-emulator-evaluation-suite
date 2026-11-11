"""reset-network-interface-attribute-invalid-attribute-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "reset-network-interface-attribute-invalid-attribute-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An efa-only ENI (no IP addresses) rejects ModifyNetworkInterfaceAttribute(SourceDestCheck)
    with InvalidParameterValue and keeps its value; the same call succeeds on an ordinary ENI.
    """
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.219.0.0/16", TagSpecifications=_tags("vpc", ctx.unique_name("sim2real-rnia-"))
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.219.1.0/24",
        TagSpecifications=_tags("subnet", ctx.unique_name("sim2real-rnia-")),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    try:
        efa_only_eni_id = ec2.create_network_interface(
            SubnetId=subnet_id,
            InterfaceType="efa-only",
            TagSpecifications=_tags(
                "network-interface", ctx.unique_name("sim2real-rnia-efa-")
            ),
        )["NetworkInterface"]["NetworkInterfaceId"]
    except Exception as exc:
        raise AssertionError(
            "this account/Region rejected creation of a standalone efa-only "
            f"network interface ({exc}); without one, the interface-type "
            "boundary this check targets cannot be constructed"
        ) from None
    ctx.on_cleanup(
        lambda: ec2.delete_network_interface(NetworkInterfaceId=efa_only_eni_id)
    )

    normal_eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=_tags(
            "network-interface", ctx.unique_name("sim2real-rnia-normal-")
        ),
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(
        lambda: ec2.delete_network_interface(NetworkInterfaceId=normal_eni_id)
    )

    baseline_efa_sdc = ec2.describe_network_interfaces(
        NetworkInterfaceIds=[efa_only_eni_id]
    )["NetworkInterfaces"][0].get("SourceDestCheck")

    # ResetNetworkInterfaceAttribute returns a generic InvalidRequest on both ENI types, so the
    # type-specific rejection is graded on Modify instead.
    code, message = _error_code_and_message(
        lambda: ec2.modify_network_interface_attribute(
            NetworkInterfaceId=efa_only_eni_id, SourceDestCheck={"Value": False}
        )
    )
    assert code == "InvalidParameterValue", (
        "expected InvalidParameterValue modifying sourceDestCheck on an "
        f"efa-only ENI, got {code!r} ({message!r})"
    )
    assert message == "Interface type: efa-only cannot modify source destination check", (
        "expected the rejection message to name both the efa-only interface "
        f"type and the source/destination check, got {message!r}"
    )

    after_efa_sdc = ec2.describe_network_interfaces(
        NetworkInterfaceIds=[efa_only_eni_id]
    )["NetworkInterfaces"][0].get("SourceDestCheck")
    assert after_efa_sdc == baseline_efa_sdc, (
        "rejected modify unexpectedly changed the efa-only interface's "
        f"SourceDestCheck from {baseline_efa_sdc!r} to {after_efa_sdc!r}"
    )

    ec2.modify_network_interface_attribute(
        NetworkInterfaceId=normal_eni_id, SourceDestCheck={"Value": False}
    )
    attrs = ec2.describe_network_interface_attribute(
        NetworkInterfaceId=normal_eni_id, Attribute="sourceDestCheck"
    )
    assert attrs["SourceDestCheck"]["Value"] is False, (
        "modify did not flip sourceDestCheck to False on an ordinary ENI, got "
        f"{attrs['SourceDestCheck']!r}"
    )


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
