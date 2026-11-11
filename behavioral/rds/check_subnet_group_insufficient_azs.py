"""subnet-group-insufficient-azs."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "subnet-group-insufficient-azs"
GROUP = 'subnet_groups'
SERVICES = ['rds']

ERR_INSUFFICIENT_AZS = "DBSubnetGroupDoesNotCoverEnoughAZs"
ERR_NOT_FOUND = "DBSubnetGroupNotFoundFault"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBSubnetGroup with only one subnet in a multi-AZ region rejects with
    DBSubnetGroupDoesNotCoverEnoughAZs, the rejected group is never created, and an
    otherwise-identical multi-AZ subnet group still succeeds.
    """
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    by_az: dict = {}
    for s in ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", []):
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("region exposes fewer than 2 AZs; AZ-coverage rule not exercisable")

    two_az_subnets = list(by_az.values())[:2]
    single_subnet = two_az_subnets[0]
    single_az = next(az for az, subnet in by_az.items() if subnet == single_subnet)

    bad_name = ctx.unique_name("sim2real-behav-sng-badaz-")
    code = message = None
    try:
        rds.create_db_subnet_group(
            DBSubnetGroupName=bad_name,
            DBSubnetGroupDescription="single az",
            SubnetIds=[single_subnet],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        # Unexpected success — register cleanup so the group doesn't leak.
        ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=bad_name))
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_INSUFFICIENT_AZS, f"unexpected error code: {code!r}"
    assert message == (
        "The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. "
        f"Current AZ coverage: {single_az}. Add subnets to cover at least 2 AZs."
    ), message

    # Effect absent: an independent read confirms the rejected group was never created.
    not_found_code = not_found_message = None
    try:
        rds.describe_db_subnet_groups(DBSubnetGroupName=bad_name)
    except ClientError as _e:
        not_found_code = _e.response.get("Error", {}).get("Code")
        not_found_message = _e.response.get("Error", {}).get("Message")
    assert not_found_code == ERR_NOT_FOUND, (
        f"rejected subnet group {bad_name!r} should not exist, got {not_found_code!r}"
    )
    assert not_found_message == f"DB Subnet group '{bad_name}' not found.", not_found_message

    # Positive control: the same call path with subnets spanning 2 distinct AZs succeeds.
    good_name = ctx.unique_name("sim2real-behav-sng-goodaz-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=good_name,
        DBSubnetGroupDescription="two az",
        SubnetIds=two_az_subnets,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=good_name))
    sg = rds.describe_db_subnet_groups(DBSubnetGroupName=good_name)["DBSubnetGroups"][0]
    assert sg["SubnetGroupStatus"] == "Complete", f"unexpected status: {sg['SubnetGroupStatus']!r}"
    assert {s["SubnetIdentifier"] for s in sg["Subnets"]} == set(two_az_subnets), sg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
