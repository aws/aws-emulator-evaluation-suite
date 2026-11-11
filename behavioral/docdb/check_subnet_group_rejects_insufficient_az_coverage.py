"""subnet-group-rejects-insufficient-az-coverage."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-group-rejects-insufficient-az-coverage"
GROUP = "rejected"
SERVICES = ["docdb"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBSubnetGroup rejects subnets that cover only one AZ with the exact
    AZ-coverage fault, and the same subnets split across two AZs succeed."""
    ec2 = ctx.client("ec2")
    docdb = ctx.client("docdb")

    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )[:2]
    assert len(azs) >= 2, f"region offers fewer than 2 available AZs: {azs!r}"

    vpc_id = ec2.create_vpc(CidrBlock="10.214.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_a = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.214.0.0/24", AvailabilityZone=azs[0]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_a))
    subnet_b = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.214.1.0/24", AvailabilityZone=azs[0]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_b))
    subnet_c = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.214.2.0/24", AvailabilityZone=azs[1]
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_c))

    group_name = ctx.unique_name("sim2real-behav-sg-az-")
    code, message = _error(
        lambda: docdb.create_db_subnet_group(
            DBSubnetGroupName=group_name,
            DBSubnetGroupDescription="sim2real behavioral check",
            SubnetIds=[subnet_a, subnet_b],
        )
    )
    assert code == "DBSubnetGroupDoesNotCoverEnoughAZs", f"expected the AZ-coverage fault, got {code!r}"
    expected = (
        "The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. "
        f"Current AZ coverage: {azs[0]}. Add subnets to cover at least 2 AZs."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    found = docdb.describe_db_subnet_groups().get("DBSubnetGroups", [])
    assert group_name not in {g["DBSubnetGroupName"] for g in found}, (
        f"rejected create_db_subnet_group must not leave a group named {group_name!r} behind"
    )

    # positive control: the same two AZs, properly covered, succeed.
    created = docdb.create_db_subnet_group(
        DBSubnetGroupName=group_name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=[subnet_a, subnet_c],
    )["DBSubnetGroup"]
    ctx.on_cleanup(lambda: docdb.delete_db_subnet_group(DBSubnetGroupName=group_name))
    assert created["SubnetGroupStatus"] == "Complete", (
        f"expected SubnetGroupStatus 'Complete', got {created['SubnetGroupStatus']!r}"
    )
    covered_subnets = {s["SubnetIdentifier"] for s in created["Subnets"]}
    assert covered_subnets == {subnet_a, subnet_c}, (
        f"expected subnets {{subnet_a, subnet_c}}, got {covered_subnets!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
