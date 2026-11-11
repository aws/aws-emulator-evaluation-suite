"""create-instance-malformed-storage-type-rejected."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-instance-malformed-storage-type-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance with an unknown StorageType is rejected with StorageTypeNotSupported and
    its exact message, and no instance exists afterwards; an otherwise identical instance with
    StorageType "gp3" succeeds and reports gp3."""
    rds = ctx.client("rds")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]

    subnet_group_name = ctx.unique_name("sim2real-rdsst-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real malformed-storage-type rejection test",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name))

    user = "s2radmin"
    password = _master_password()

    bad_id = ctx.unique_name("sim2real-rdsst-bad-")
    # Cleans up the instance if the create is wrongly accepted; DBInstanceNotFound is ignored.
    ctx.on_cleanup(lambda: _best_effort_delete_instance(rds, bad_id))
    code, message = _error_code(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=bad_id,
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            AllocatedStorage=20,
            MasterUsername=user,
            MasterUserPassword=password,
            DBSubnetGroupName=subnet_group_name,
            StorageType="turbo-ssd-9000",
            Tags=[{"Key": "sim2real", "Value": "true"}],
        ),
        unexpected_success_label="CreateDBInstance with StorageType='turbo-ssd-9000'",
    )
    assert code == "StorageTypeNotSupported", (
        f"expected StorageTypeNotSupported for StorageType='turbo-ssd-9000', got {code!r}"
    )
    expected = "Invalid storage type: turbo-ssd-9000"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected instance must not exist afterwards.
    not_found_code, not_found_message = _error_code(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=bad_id),
        unexpected_success_label=f"DescribeDBInstances({bad_id!r}) after its rejected create",
    )
    assert not_found_code == "DBInstanceNotFound", (
        f"rejected instance {bad_id!r} should not exist, but describe returned "
        f"code={not_found_code!r} instead of DBInstanceNotFound"
    )
    expected_nf = f"DBInstance {bad_id} not found."
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

    good_id = ctx.unique_name("sim2real-rdsst-good-")
    rds.create_db_instance(
        DBInstanceIdentifier=good_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        AllocatedStorage=20,
        MasterUsername=user,
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        StorageType="gp3",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup_instance() -> None:
        rds.delete_db_instance(DBInstanceIdentifier=good_id, SkipFinalSnapshot=True)
        rds.get_waiter("db_instance_deleted").wait(
            DBInstanceIdentifier=good_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
        )

    ctx.on_cleanup(_cleanup_instance)

    rds.get_waiter("db_instance_available").wait(
        DBInstanceIdentifier=good_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    desc = rds.describe_db_instances(DBInstanceIdentifier=good_id)["DBInstances"][0]
    assert desc["StorageType"] == "gp3", (
        f"positive-control instance {good_id!r} should have StorageType='gp3', "
        f"got {desc['StorageType']!r}"
    )


def _master_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


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


def _error_code(fn, *, unexpected_success_label: str) -> tuple[str, str]:
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"{unexpected_success_label}: expected a ClientError, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete_instance(rds, inst_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
