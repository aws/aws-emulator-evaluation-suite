"""subnet-group-lifecycle-crud."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-group-lifecycle-crud"
GROUP = "control-plane"
SERVICES = ["dax"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create -> describe -> update -> delete a DAX subnet group against subnets in a
    VPC this check provisions itself, asserting the subnet membership and description
    actually persist and that the group disappears after deletion."""
    subnet_ids = _create_subnet_group_subnets(ctx, count=2)
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-sng-")
    dax.create_subnet_group(SubnetGroupName=name, Description="sim2real initial", SubnetIds=subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, name))

    described = dax.describe_subnet_groups(SubnetGroupNames=[name])["SubnetGroups"][0]
    assert described["SubnetGroupName"] == name, (
        f"expected describe_subnet_groups to return name {name!r}, got {described['SubnetGroupName']!r}"
    )
    assert described["Description"] == "sim2real initial", (
        f"expected initial description 'sim2real initial', got {described['Description']!r}"
    )
    described_subnet_ids = {s["SubnetIdentifier"] for s in described["Subnets"]}
    assert described_subnet_ids == set(subnet_ids), (
        f"expected member subnets {set(subnet_ids)!r}, got {described_subnet_ids!r}"
    )

    dax.update_subnet_group(SubnetGroupName=name, Description="sim2real updated")
    updated = dax.describe_subnet_groups(SubnetGroupNames=[name])["SubnetGroups"][0]
    assert updated["Description"] == "sim2real updated", (
        f"expected updated description 'sim2real updated', got {updated['Description']!r}"
    )

    dax.delete_subnet_group(SubnetGroupName=name)
    code, message = _expect_error(lambda: dax.describe_subnet_groups(SubnetGroupNames=[name]))
    assert code == "SubnetGroupNotFoundFault", (
        f"expected SubnetGroupNotFoundFault describing a deleted subnet group, got {code!r}"
    )
    assert message == f"Subnet group {name} not found.", f"unexpected message: {message!r}"

    update_code, update_message = _expect_error(lambda: dax.update_subnet_group(SubnetGroupName=name, Description="post-delete"))
    assert update_code == "SubnetGroupNotFoundFault", (
        f"expected a mutation on the deleted subnet group's name to fail with SubnetGroupNotFoundFault, got {update_code!r}"
    )
    assert update_message == f"Subnet Group {name} does not exist.", f"unexpected message: {update_message!r}"

    dax.create_subnet_group(SubnetGroupName=name, Description="sim2real recreated", SubnetIds=subnet_ids)
    recreated = dax.describe_subnet_groups(SubnetGroupNames=[name])["SubnetGroups"][0]
    assert recreated["Description"] == "sim2real recreated", (
        f"expected the deleted subnet group's name to be reusable, got description {recreated['Description']!r}"
    )


# ===== helpers =====
def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target accepting what AWS refuses must not be reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    """Teardown: a resource that is already gone is fine; every other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "SubnetGroupNotFoundFault",
            "InvalidVpcID.NotFound",
            "InvalidSubnetID.NotFound",
        ):
            raise


def _safe_delete_subnet_group(ctx, name):
    _safe(lambda: ctx.client("dax").delete_subnet_group(SubnetGroupName=name))


def _create_subnet_group_subnets(ctx, count=2):
    """Provision a private VPC + subnets for this check, rather than depending on an
    ambient default VPC that a freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"][:count]
    ]
    if len(azs) < count:
        raise AssertionError(f"region does not expose {count} available AZs for a DAX subnet group")

    tag = ctx.unique_name("sim2real-dax-sng-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.223.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.223.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)

    return subnet_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
