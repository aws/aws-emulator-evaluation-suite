"""resource-share-without-external-principal-has-no-resource-policy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-share-without-external-principal-has-no-resource-policy"
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
            return associations[0]
        time.sleep(2.0)
    raise AssertionError(f"association never reached {status!r}, last seen {last!r}")


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Sharing a resource with no external principal associates it, but RAM never
    attaches a resource-based policy for a share that never crossed an account."""
    ec2 = ctx.client("ec2")
    ram = ctx.client("ram")

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    az = _usable_az(ec2)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.91.1.0/24", AvailabilityZone=az
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound")
    )
    subnet_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:subnet/{subnet_id}"

    name = ctx.unique_name("sim2real-ram-nopolicy-")
    share = ram.create_resource_share(
        name=name,
        resourceArns=[subnet_arn],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )

    # Positive control: the share did take effect, proving the account and the
    # association path are healthy.
    _wait_association_status(ram, share_arn, subnet_arn, "ASSOCIATED")

    # Effect absent: no resource-based policy exists for the subnet, because no
    # principal outside this account was ever granted access to it.
    policy_pages = ram.get_paginator("get_resource_policies").paginate(
        resourceArns=[subnet_arn]
    )
    policies = [p for page in policy_pages for p in page["policies"]]
    assert policies == [], (
        f"expected no resource policy for a same-account-only share, got {policies!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
