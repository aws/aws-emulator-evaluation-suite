"""db-subnet-group-insufficient-azs-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-subnet-group-insufficient-azs-rejected"
GROUP = "deploy"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBSubnetGroup with subnets in one AZ fails with DBSubnetGroupDoesNotCoverEnoughAZs
    and its exact message and creates nothing; a two-AZ group succeeds, and after deletion
    describe and modify report it not found."""
    subnet_ids = _pick_two_az_subnets(ctx)
    rds = ctx.client("rds")

    bad_name = ctx.unique_name("sim2real-rds-sng-bad-")
    code, message = _error_code(lambda: rds.create_db_subnet_group(
        DBSubnetGroupName=bad_name,
        DBSubnetGroupDescription="sim2real single-az rejection check",
        SubnetIds=[subnet_ids[0]],
    ))
    assert code == "DBSubnetGroupDoesNotCoverEnoughAZs", code
    single_az = _subnet_az(ctx, subnet_ids[0])
    assert message == (
        "The DB subnet group doesn't meet Availability Zone (AZ) coverage requirement. "
        f"Current AZ coverage: {single_az}. Add subnets to cover at least 2 AZs."
    ), message

    not_found_code, not_found_message = _error_code(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=bad_name)
    )
    assert not_found_code == "DBSubnetGroupNotFoundFault", not_found_code
    assert not_found_message == f"DB Subnet group '{bad_name}' not found.", not_found_message

    good_name = ctx.unique_name("sim2real-rds-sng-good-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=good_name,
        DBSubnetGroupDescription="sim2real multi-az control",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_if_present(rds, good_name))
    sg = rds.describe_db_subnet_groups(DBSubnetGroupName=good_name)["DBSubnetGroups"][0]
    assert sg["SubnetGroupStatus"] == "Complete", sg["SubnetGroupStatus"]
    assert {s["SubnetIdentifier"] for s in sg["Subnets"]} == set(subnet_ids), sg

    rds.delete_db_subnet_group(DBSubnetGroupName=good_name)
    gone_code, gone_message = _error_code(
        lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=good_name)
    )
    assert gone_code == "DBSubnetGroupNotFoundFault", gone_code
    assert gone_message == f"DB Subnet group '{good_name}' not found.", gone_message
    mutate_code, mutate_message = _error_code(
        lambda: rds.modify_db_subnet_group(DBSubnetGroupName=good_name, SubnetIds=subnet_ids)
    )
    assert mutate_code == "DBSubnetGroupNotFoundFault", mutate_code
    assert mutate_message == f"DB subnet group '{good_name}' does not exist.", mutate_message


def _error_code(fn):
    """Call fn() and return its error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _subnet_az(ctx, subnet_id):
    ec2 = ctx.client("ec2")
    return ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["AvailabilityZone"]


def _delete_if_present(rds, name):
    try:
        rds.delete_db_subnet_group(DBSubnetGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBSubnetGroupNotFoundFault":
            raise


def _pick_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            f"VPC {vpc_id} does not span at least 2 AZs; cannot exercise the "
            "insufficient-AZ rejection path"
        )
    return list(by_az.values())[:2]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
