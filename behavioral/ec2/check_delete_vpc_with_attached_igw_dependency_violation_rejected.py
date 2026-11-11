"""delete-vpc-with-attached-igw-dependency-violation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vpc-with-attached-igw-dependency-violation-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a VPC that still has an attached internet gateway is rejected; detaching first allows deletion."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpcigw-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.174.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    deleted = {"value": False}

    def _cleanup_vpc():
        if not deleted["value"]:
            ec2.delete_vpc(VpcId=vpc_id)

    ctx.on_cleanup(_cleanup_vpc)
    _wait_vpc_available(ec2, vpc_id)

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "1"}]}],
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    detached = {"value": False}

    def _cleanup_igw():
        if not detached["value"]:
            ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        ec2.delete_internet_gateway(InternetGatewayId=igw_id)

    ctx.on_cleanup(_cleanup_igw)

    error = _error(lambda: ec2.delete_vpc(VpcId=vpc_id))
    assert error["Code"] == "DependencyViolation", error
    assert error.get("Message") == f"The vpc '{vpc_id}' has dependencies and cannot be deleted.", error

    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    assert len(vpcs) == 1, "VPC should still exist after the rejected delete"

    ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    detached["value"] = True
    ec2.delete_vpc(VpcId=vpc_id)
    deleted["value"] = True

    after = _error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]))
    assert after["Code"] == "InvalidVpcID.NotFound", after
    assert after.get("Message") == f"The vpc ID '{vpc_id}' does not exist", after

    double_delete = _error(lambda: ec2.delete_vpc(VpcId=vpc_id))
    assert double_delete["Code"] == "InvalidVpcID.NotFound", double_delete
    assert double_delete.get("Message") == f"The vpc ID '{vpc_id}' does not exist", double_delete


def _wait_vpc_available(ec2, vpc_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        if vpc["State"] == "available":
            return
        time.sleep(2)
    raise AssertionError("VPC never became available")


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
