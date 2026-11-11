"""op-contract-delete-network-interface."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-network-interface"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkInterface removes an unattached ENI; deleting an unknown ENI ID
    is rejected with InvalidNetworkInterfaceID.NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-eni-")

    vpc_id = ec2.create_vpc(CidrBlock="10.84.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.84.1.0/24", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=[_tag_spec("network-interface", name)]
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id)))

    ec2.delete_network_interface(NetworkInterfaceId=eni_id)

    code, message = _error(lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id]))
    assert code == "InvalidNetworkInterfaceID.NotFound", f"unexpected error describing the deleted ENI: {code}: {message}"
    assert message == f"The networkInterface ID '{eni_id}' does not exist", message

    bogus_id = "eni-00000000000000000"
    code, message = _error(lambda: ec2.delete_network_interface(NetworkInterfaceId=bogus_id))
    assert code == "InvalidNetworkInterfaceID.NotFound", f"unexpected error deleting an unknown ENI: {code}: {message}"
    assert message == f"The networkInterface ID '{bogus_id}' does not exist", message


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
