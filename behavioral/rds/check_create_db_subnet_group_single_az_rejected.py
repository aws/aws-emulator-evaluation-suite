"""create-db-subnet-group-single-az-rejected."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "create-db-subnet-group-single-az-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBSubnetGroup with subnets in a single Availability Zone is rejected with
    DBSubnetGroupDoesNotCoverEnoughAZs and creates no group, while subnets spanning two zones of the
    same VPC succeed."""
    rds = ctx.client("rds")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    single_az_subnet = az_subnets[0]["SubnetId"]
    two_az_subnets = [s["SubnetId"] for s in az_subnets]

    # --- negative: all subnets in exactly one AZ, while the VPC has >=2 AZs available ---
    bad_name = ctx.unique_name("sim2real-rds-1az-")
    single_az = az_subnets[0]["AvailabilityZone"]
    code, message = _error_code(
        lambda: rds.create_db_subnet_group(
            DBSubnetGroupName=bad_name,
            DBSubnetGroupDescription="sim2real single-AZ rejection test",
            SubnetIds=[single_az_subnet],
        ),
        on_unexpected_success=lambda: ctx.on_cleanup(
            lambda: rds.delete_db_subnet_group(DBSubnetGroupName=bad_name)
        ),
    )
    assert code == "DBSubnetGroupDoesNotCoverEnoughAZs", (
        f"expected DBSubnetGroupDoesNotCoverEnoughAZs for a single-AZ subnet group, got {code!r}"
    )
    expected = (
        "The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. "
        f"Current AZ coverage: {single_az}. Add subnets to cover at least 2 AZs."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected subnet group must not actually exist afterwards.
    not_found_code, not_found_message = _error_code(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=bad_name)
    )
    assert not_found_code == "DBSubnetGroupNotFoundFault", (
        f"rejected subnet group {bad_name!r} should not exist, but describe returned "
        f"code={not_found_code!r} instead of DBSubnetGroupNotFoundFault"
    )
    expected_nf = f"DB Subnet group '{bad_name}' not found."
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

    # --- positive control: subnets spanning 2 distinct AZs succeed, in the same VPC ---
    good_name = ctx.unique_name("sim2real-rds-2az-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=good_name,
        DBSubnetGroupDescription="sim2real two-AZ positive control",
        SubnetIds=two_az_subnets,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=good_name))

    created = rds.describe_db_subnet_groups(DBSubnetGroupName=good_name)["DBSubnetGroups"][0]
    created_azs = {s["SubnetAvailabilityZone"]["Name"] for s in created["Subnets"]}
    assert len(created_azs) >= 2, (
        f"positive-control subnet group {good_name!r} should cover >=2 AZs, got {created_azs}"
    )


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
    """Return (vpc_id, [subnet, ...]) covering `count` distinct AZs, for a DBSubnetGroup."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < count:
        raise AssertionError(
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for an RDS subnet group"
        )
    return vpc_id, list(by_az.values())[:count]


def _error_code(fn, *, on_unexpected_success=None) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    if on_unexpected_success is not None:
        on_unexpected_success()
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
