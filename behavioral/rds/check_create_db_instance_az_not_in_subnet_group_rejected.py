"""create-db-instance-az-not-in-subnet-group-rejected."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "create-db-instance-az-not-in-subnet-group-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBInstance in an AvailabilityZone its DB subnet group does not cover is rejected with
    InvalidVPCNetworkStateFault, while an identical instance in a covered zone lands in exactly it."""
    rds = ctx.client("rds")
    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=3)
    covered = az_subnets[:2]
    outside_az = az_subnets[2]["AvailabilityZone"]
    covered_az = covered[0]["AvailabilityZone"]
    subnet_ids = [s["SubnetId"] for s in covered]

    subnet_group_name = ctx.unique_name("sim2real-rdsaz-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real AZ-not-in-subnet-group rejection test",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "owner", "Value": "compatibility"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name))

    user = "s2radmin"
    password = _admin_password()

    # --- negative: AvailabilityZone outside the subnet group's covered AZs ---
    bad_id = ctx.unique_name("sim2real-rdsaz-bad-")
    # Registered before the call: if the target is over-permissive and actually creates the
    # instance despite the rejected AZ, this must still be torn down.
    ctx.on_cleanup(lambda: _delete_if_present(rds, bad_id))
    code, message = _error(
        lambda: rds.create_db_instance(
            DBInstanceIdentifier=bad_id,
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            AllocatedStorage=20,
            MasterUsername=user,
            MasterUserPassword=password,
            DBSubnetGroupName=subnet_group_name,
            AvailabilityZone=outside_az,
            Tags=[{"Key": "owner", "Value": "compatibility"}],
        )
    )
    assert code == "InvalidVPCNetworkStateFault", (
        f"expected InvalidVPCNetworkStateFault for AvailabilityZone={outside_az!r} not covered "
        f"by subnet group {subnet_group_name!r}, got {code!r}"
    )
    covered_list = ", ".join(sorted(s["AvailabilityZone"] for s in covered))
    expected = (
        "You can't create a db.t3.micro database instance because there are no subnets with "
        f"available IP addresses in the specified Availability Zone {outside_az}. Create a new "
        f"subnet in {outside_az} and target that Availability Zone again, or retry the launch "
        f"with no availability zone, or choose from these Availability Zones: {covered_list}."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected instance must not exist afterwards, in any AZ.
    not_found_code, not_found_message = _error(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=bad_id)
    )
    assert not_found_code == "DBInstanceNotFound", (
        f"rejected instance {bad_id!r} should not exist, but describe returned "
        f"code={not_found_code!r} instead of DBInstanceNotFound"
    )
    expected_nf = f"DBInstance {bad_id} not found."
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

    # --- positive control: an AZ the subnet group DOES cover succeeds and lands there ---
    good_id = ctx.unique_name("sim2real-rdsaz-good-")
    rds.create_db_instance(
        DBInstanceIdentifier=good_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        AllocatedStorage=20,
        MasterUsername=user,
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        AvailabilityZone=covered_az,
        Tags=[{"Key": "owner", "Value": "compatibility"}],
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
    assert desc["AvailabilityZone"] == covered_az, (
        f"positive-control instance {good_id!r} should land in {covered_az!r}, "
        f"got {desc['AvailabilityZone']!r}"
    )


def _admin_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
    """Return (vpc_id, [subnet, ...]) covering `count` distinct AZs."""
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
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} AZs "
            f"(2 to cover the subnet group + 1 outside it) for this test"
        )
    return vpc_id, list(by_az.values())[:count]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_if_present(rds, db_instance_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_instance_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=db_instance_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
