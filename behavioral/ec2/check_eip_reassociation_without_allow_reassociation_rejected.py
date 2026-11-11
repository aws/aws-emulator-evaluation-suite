"""eip-reassociation-without-allow-reassociation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eip-reassociation-without-allow-reassociation-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-associating an already-associated EIP to a different ENI with AllowReassociation=False is
    rejected. (AssociateAddress defaults AllowReassociation to true, so the flag must be passed
    explicitly to exercise the rejection.)"""
    ec2 = ctx.client("ec2")
    tag_spec = lambda resource_type: [
        {"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": "1"}]}
    ]
    vpc_id = ec2.create_vpc(CidrBlock="10.173.0.0/16", TagSpecifications=tag_spec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.173.1.0/24", TagSpecifications=tag_spec("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    # AssociateAddress rejects with Gateway.NotAttached on a VPC with no internet gateway.
    igw_id = ec2.create_internet_gateway(TagSpecifications=tag_spec("internet-gateway"))[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))

    eni1 = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=tag_spec("network-interface")
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni1))
    eni2 = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=tag_spec("network-interface")
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni2))

    alloc = ec2.allocate_address(Domain="vpc", TagSpecifications=tag_spec("elastic-ip"))
    allocation_id = alloc["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=allocation_id))

    assoc1 = ec2.associate_address(AllocationId=allocation_id, NetworkInterfaceId=eni1)
    ctx.on_cleanup(lambda: _safe_disassociate(ec2, allocation_id))
    assert assoc1["AssociationId"]

    code, message = _error(
        lambda: ec2.associate_address(
            AllocationId=allocation_id, NetworkInterfaceId=eni2, AllowReassociation=False
        )
    )
    assert code == "Resource.AlreadyAssociated", f"expected Resource.AlreadyAssociated, got {code}"
    assert message == (f"resource {allocation_id} is already associated with associate-id "
                       f"{assoc1['AssociationId']}"), message

    addr = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"][0]
    assert addr.get("NetworkInterfaceId") == eni1, "reassociation should not have moved the address"

    ec2.associate_address(AllocationId=allocation_id, NetworkInterfaceId=eni2, AllowReassociation=True)
    addr_after = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"][0]
    assert (
        addr_after.get("NetworkInterfaceId") == eni2
    ), "positive-control reassociation with AllowReassociation=True should have succeeded"


def _wait_vpc_available(ec2, vpc_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        if vpc["State"] == "available":
            return
        time.sleep(2)
    raise AssertionError("VPC never became available")


def _safe_disassociate(ec2, allocation_id):
    try:
        addr = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"][0]
        assoc_id = addr.get("AssociationId")
        if assoc_id:
            ec2.disassociate_address(AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAllocationID.NotFound",
            "InvalidAssociationID.NotFound",
        ):
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
