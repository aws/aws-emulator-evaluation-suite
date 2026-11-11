"""delete-nonexistent-instance."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-instance"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"
_USER = "sim2real"
_PASS = "Sim2Real#Pass99"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _poll(fn, pred, *, timeout_s, interval_s=15):
    """Poll fn() until pred(value) or the deadline; returns the last value seen."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _instance(rds, inst_id):
    """DescribeDBInstances for one id, or None when it no longer exists."""
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_DB_INSTANCE_NOT_FOUND:
            return None
        raise


def _wait_instance_available(rds, inst_id, *, timeout_s=2100):
    """Poll a DB instance to 'available' and return its describe payload."""
    inst = _poll(
        lambda: _instance(rds, inst_id),
        lambda i: i is not None and i.get("DBInstanceStatus") == "available",
        timeout_s=timeout_s,
    )
    assert inst is not None, f"DB instance {inst_id} vanished while waiting for 'available'"
    assert inst["DBInstanceStatus"] == "available", (
        f"DB instance {inst_id} did not reach 'available' within {timeout_s}s; "
        f"last status {inst['DBInstanceStatus']!r}"
    )
    return inst


def _delete_instance_best_effort(rds, inst_id):
    """Teardown: delete an instance with no final snapshot and wait until it is gone."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_DB_INSTANCE_NOT_FOUND:
            return
        raise
    gone = _poll(
        lambda: _instance(rds, inst_id), lambda i: i is None, timeout_s=1800, interval_s=20
    )
    assert gone is None, f"teardown: DB instance {inst_id} still exists after 1800s"


def _client_error(fn):
    """(code, message) of the ClientError fn() raises; AssertionError when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _default_engine_version(rds, engine):
    """The engine's current default version, or None when the catalog is unavailable."""
    try:
        versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
            "DBEngineVersions", []
        )
    except ClientError:
        return None
    return versions[0]["EngineVersion"] if versions else None


def _await_enis_clear(ec2, subnet_id, timeout_s=900, interval_s=15):
    """Wait out RDS ENIs left in a subnet of this check's own VPC after the instance is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )["NetworkInterfaces"]
        if not enis:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"subnet {subnet_id} still has {len(enis)} ENI(s) after {timeout_s}s: "
                f"{[e['NetworkInterfaceId'] for e in enis]}"
            )
        time.sleep(interval_s)


def _delete_with_retry(fn, timeout_s=300, interval_s=15):
    """Run an EC2 delete, retrying DependencyViolation until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _own_subnet_group(ctx):
    """A DB subnet group over a two-AZ VPC this check creates; all of it registered for cleanup."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= 2, f"region {ctx.region!r} has only {len(azs)} available AZ(s); need 2"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.194.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.194.0.{i * 16}/28",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
        )["Subnet"]["SubnetId"]

        def _drop_subnet(sid=subnet_id):
            _await_enis_clear(ec2, sid)
            _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=sid))

        ctx.on_cleanup(_drop_subnet)
        subnet_ids.append(subnet_id)
    name = ctx.unique_name("sim2real-behav-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBInstance succeeds on a real instance, which DescribeDBInstances then reports gone, and a
    second delete of that id and a delete of a never-created id are both rejected with
    DBInstanceNotFound."""
    rds = ctx.client("rds")
    version = _default_engine_version(rds, "postgres")

    real_id = ctx.unique_name("sim2real-behav-inst-")
    ghost_id = ctx.unique_name("sim2real-behav-inst-")

    create = {
        "DBInstanceIdentifier": real_id,
        "Engine": "postgres",
        "DBInstanceClass": "db.t3.micro",
        "AllocatedStorage": 20,
        "MasterUsername": _USER,
        "MasterUserPassword": _PASS,
        "BackupRetentionPeriod": 0,
        "DeletionProtection": False,
        "DBSubnetGroupName": _own_subnet_group(ctx),
        "PubliclyAccessible": False,
        "Tags": _MANAGED_TAGS,
    }
    if version:
        create["EngineVersion"] = version
    rds.create_db_instance(**create)
    ctx.on_cleanup(lambda: _delete_instance_best_effort(rds, real_id))
    _wait_instance_available(rds, real_id)

    # --- Positive control: DeleteDBInstance on a real, available instance is accepted.
    resp = rds.delete_db_instance(DBInstanceIdentifier=real_id, SkipFinalSnapshot=True)
    assert resp["DBInstance"]["DBInstanceIdentifier"] == real_id, (
        "positive control failed: DeleteDBInstance on a real, available instance did not "
        f"return that instance, got {resp['DBInstance'].get('DBInstanceIdentifier')!r}"
    )
    assert resp["DBInstance"]["DBInstanceStatus"] == "deleting", (
        "positive control failed: DeleteDBInstance on a real, available instance did not "
        f"report 'deleting', got {resp['DBInstance']['DBInstanceStatus']!r}"
    )

    # --- Independent read, a different op than the delete: the real instance is really gone.
    gone = _poll(
        lambda: _instance(rds, real_id), lambda i: i is None, timeout_s=1800, interval_s=20
    )
    assert gone is None, (
        f"the deleted instance {real_id} should be gone; DescribeDBInstances still reports "
        f"{gone.get('DBInstanceStatus')!r}"
    )

    # --- A further mutation on the now-dead real id fails with the specific not-found code.
    code, message = _client_error(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=real_id, SkipFinalSnapshot=True)
    )
    assert code == ERR_DB_INSTANCE_NOT_FOUND, f"expected {ERR_DB_INSTANCE_NOT_FOUND}, got {code!r}"
    assert message == f"DBInstance {real_id} not found.", f"unexpected error message {message!r}"

    # --- The declared subject: an id that was never created at all is rejected the same way.
    code, message = _client_error(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=ghost_id, SkipFinalSnapshot=True)
    )
    assert code == ERR_DB_INSTANCE_NOT_FOUND, f"expected {ERR_DB_INSTANCE_NOT_FOUND}, got {code!r}"
    assert message == f"DBInstance {ghost_id} not found.", f"unexpected error message {message!r}"

    # --- Terminal independent read, at the destination, through yet another op than the delete.
    code, message = _client_error(lambda: rds.describe_db_instances(DBInstanceIdentifier=ghost_id))
    assert code == ERR_DB_INSTANCE_NOT_FOUND, f"expected {ERR_DB_INSTANCE_NOT_FOUND}, got {code!r}"
    assert message == f"DBInstance {ghost_id} not found.", f"unexpected error message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
