"""op-contract-reset-network-interface-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-reset-network-interface-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResetNetworkInterfaceAttribute reverts sourceDestCheck to its default (true) and
    rejects a request against a non-existent ENI with InvalidNetworkInterfaceID.NotFound."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-reset-nic-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description=ctx.unique_name("sim2real-eni-"),
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": [{"Key": "Name", "Value": name}]}],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    # The default is True; set it to False so the reset is observable.
    ec2.modify_network_interface_attribute(
        NetworkInterfaceId=eni_id, SourceDestCheck={"Value": False}
    )
    desc = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    assert desc["SourceDestCheck"] is False, "modify did not flip sourceDestCheck to False"

    # SourceDestCheck is a string, but EC2 rejects any non-empty value (even "true") with
    # InvalidRequest; its presence alone requests the reset to the default (true).
    ec2.reset_network_interface_attribute(NetworkInterfaceId=eni_id, SourceDestCheck="")
    desc = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    assert desc["SourceDestCheck"] is True, "reset did not restore sourceDestCheck default (True)"

    # The documented placeholder id passes format validation; ad hoc hex strings can be
    # rejected as malformed before the existence check.
    code, message = _client_error(
        lambda: ec2.reset_network_interface_attribute(
            NetworkInterfaceId="eni-1234567890abcdef0", SourceDestCheck=""
        )
    )
    assert code == "InvalidNetworkInterfaceID.NotFound", f"unexpected error code: {code}"
    expected_message = "The networkInterface ID 'eni-1234567890abcdef0' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected a ClientError, but the call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
