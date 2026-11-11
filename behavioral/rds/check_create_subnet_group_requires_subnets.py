"""create-subnet-group-requires-subnets."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-subnet-group-requires-subnets"
GROUP = 'subnet_groups'
SERVICES = ['rds']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBSubnetGroup with an empty SubnetIds list is rejected with InvalidSubnet and creates no
    group, while the same call with a multi-AZ subnet list succeeds."""
    rds = ctx.client("rds")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    good_subnets = [s["SubnetId"] for s in az_subnets]

    # Positive control: the same call shape with real subnets succeeds.
    good_name = ctx.unique_name("sim2real-behav-sng-good-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=good_name,
        DBSubnetGroupDescription="sim2real positive control",
        SubnetIds=good_subnets,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=good_name))
    created = rds.describe_db_subnet_groups(DBSubnetGroupName=good_name)["DBSubnetGroups"][0]
    assert {s["SubnetIdentifier"] for s in created["Subnets"]} == set(good_subnets), (
        f"positive-control subnet group {good_name!r} does not list the requested subnets: {created!r}"
    )

    # Negative: an empty SubnetIds list is rejected with the specific error, not merely "some" error.
    bad_name = ctx.unique_name("sim2real-behav-sng-empty-")
    error = _client_error(lambda: rds.create_db_subnet_group(
        DBSubnetGroupName=bad_name,
        DBSubnetGroupDescription="sim2real empty-subnets rejection test",
        SubnetIds=[],
    ))
    assert error.get("Code") == "InvalidSubnet", (
        f"expected InvalidSubnet for an empty SubnetIds list, got {error.get('Code')!r} "
        f"(message={error.get('Message')!r})"
    )
    assert error.get("Message") == "Subnet IDs are required.", (
        f"the rejection message was {error.get('Message')!r}, expected 'Subnet IDs are required.'"
    )

    # Effect-absent: the rejected subnet group was never created.
    not_found = _client_error(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=bad_name)
    )
    not_found_code = not_found.get("Code")
    assert not_found_code == "DBSubnetGroupNotFoundFault", (
        f"rejected subnet group {bad_name!r} should not exist, but describe returned "
        f"code={not_found_code!r} instead of DBSubnetGroupNotFoundFault"
    )
    expected_nf = f"DB Subnet group '{bad_name}' not found."
    assert not_found.get("Message") == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found.get('Message')!r}"
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


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
