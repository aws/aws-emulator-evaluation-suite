"""disassociate-resource-share-removes-association-not-resource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-resource-share-removes-association-not-resource"
GROUP = "resource-share-lifecycle"
SERVICES = ["ram"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _usable_az(ec2) -> str:
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone"
        )["InstanceTypeOfferings"]
    }
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert zones, "no available AZ reported any instance type offering"
    return zones[0]


def _wait_association_status(ram, share_arn: str, resource_arn: str, status: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        pages = ram.get_paginator("get_resource_share_associations").paginate(
            associationType="RESOURCE", resourceShareArns=[share_arn], resourceArn=resource_arn
        )
        associations = [a for page in pages for a in page["resourceShareAssociations"]]
        assert len(associations) == 1, f"expected exactly 1 association, got {associations!r}"
        last = associations[0]["status"]
        if last == status:
            return last
        time.sleep(2.0)
    raise AssertionError(f"association never reached {status!r}, last seen {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateResourceShare removes the share's association with a resource
    without deleting the resource itself, which stays describable afterward."""
    ec2 = ctx.client("ec2")
    ram = ctx.client("ram")

    vpc_id = ec2.create_vpc(CidrBlock="10.92.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    az = _usable_az(ec2)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.92.1.0/24", AvailabilityZone=az
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound")
    )
    subnet_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:subnet/{subnet_id}"

    name = ctx.unique_name("sim2real-ram-disassoc-")
    share = ram.create_resource_share(
        name=name,
        resourceArns=[subnet_arn],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )

    _wait_association_status(ram, share_arn, subnet_arn, "ASSOCIATED")

    ram.disassociate_resource_share(resourceShareArn=share_arn, resourceArns=[subnet_arn])
    _wait_association_status(ram, share_arn, subnet_arn, "DISASSOCIATED")

    # The resource itself is untouched by the disassociation.
    subnets = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
    assert len(subnets) == 1 and subnets[0]["SubnetId"] == subnet_id, (
        f"expected the subnet to still exist after disassociation, got {subnets!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
