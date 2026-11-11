"""delete-without-final-snapshot-identifier-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-without-final-snapshot-identifier-rejected"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

ERR_INVALID_PARAMETER_COMBINATION = "InvalidParameterCombination"
ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"
_MSG_NO_FINAL_SNAPSHOT_ID = (
    "FinalDBSnapshotIdentifier is required unless SkipFinalSnapshot is specified."
)
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


def _delete_instance(rds, inst_id):
    """Teardown: delete an instance with no final snapshot and wait until it is gone."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=inst_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
    except ClientError as exc:
        # InvalidDBInstanceState: the instance is already deleting; wait it out below.
        if exc.response.get("Error", {}).get("Code") not in (
            ERR_DB_INSTANCE_NOT_FOUND,
            "InvalidDBInstanceState",
        ):
            raise
    gone = _poll(
        lambda: _instance(rds, inst_id), lambda i: i is None, timeout_s=1800, interval_s=20
    )
    assert gone is None, f"teardown: DB instance {inst_id} still exists after 1800s"


def _drop_snapshot(rds, snap_id):
    """Best-effort snapshot teardown."""
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise


def _snapshot(rds, snap_id):
    """DescribeDBSnapshots for one id, or None when it does not exist."""
    try:
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DBSnapshotNotFound":
            return None
        raise


def _client_error(fn):
    """The ClientError fn() raises; AssertionError when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc
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




@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDBInstance(SkipFinalSnapshot=False) without FinalDBSnapshotIdentifier fails
    InvalidParameterCombination and leaves the instance 'available'; with a snapshot name the delete
    proceeds and the named manual snapshot appears.
    """
    rds = ctx.client("rds")
    version = _default_engine_version(rds, "postgres")

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    create = {
        "DBInstanceIdentifier": inst_id,
        "Engine": "postgres",
        "DBInstanceClass": "db.t3.micro",
        "AllocatedStorage": 20,
        "MasterUsername": _USER,
        "MasterUserPassword": _PASS,
        "BackupRetentionPeriod": 0,
        "DeletionProtection": False,
        "CopyTagsToSnapshot": True,
        "DBSubnetGroupName": _own_subnet_group(ctx),
        "PubliclyAccessible": False,
        "Tags": _MANAGED_TAGS,
    }
    if version:
        create["EngineVersion"] = version
    rds.create_db_instance(**create)
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))
    _wait_instance_available(rds, inst_id)

    # --- Break exactly one thing: request a final snapshot without naming it.
    exc = _client_error(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=False)
    )
    code = exc.response.get("Error", {}).get("Code")
    assert code == ERR_INVALID_PARAMETER_COMBINATION, (
        f"expected {ERR_INVALID_PARAMETER_COMBINATION}, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == _MSG_NO_FINAL_SNAPSHOT_ID, f"unexpected error message {message!r}"
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 400, f"expected HTTP 400 for the parameter-combination refusal, got {status!r}"

    # --- Effect absent: the refusal must not have started a deletion.
    live = _instance(rds, inst_id)
    assert live is not None, "the rejected delete removed the instance anyway"
    assert live["DBInstanceStatus"] == "available", (
        "a rejected DeleteDBInstance must leave the instance untouched; status is "
        f"{live['DBInstanceStatus']!r}"
    )

    # --- Omitting the flag entirely defaults to SkipFinalSnapshot=False: same refusal.
    exc = _client_error(lambda: rds.delete_db_instance(DBInstanceIdentifier=inst_id))
    assert exc.response.get("Error", {}).get("Code") == ERR_INVALID_PARAMETER_COMBINATION, (
        f"expected {ERR_INVALID_PARAMETER_COMBINATION} for the defaulted flag, got "
        f"{exc.response.get('Error', {}).get('Code')!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == _MSG_NO_FINAL_SNAPSHOT_ID, f"unexpected error message {message!r}"
    assert (_instance(rds, inst_id) or {}).get("DBInstanceStatus") == "available"

    # --- Control case: the same delete WITH a snapshot name is accepted and does the backup.
    snap_id = ctx.unique_name("sim2real-behav-final-")
    ctx.on_cleanup(lambda: _drop_snapshot(rds, snap_id))
    resp = rds.delete_db_instance(
        DBInstanceIdentifier=inst_id,
        SkipFinalSnapshot=False,
        FinalDBSnapshotIdentifier=snap_id,
    )
    assert resp["DBInstance"]["DBInstanceIdentifier"] == inst_id, (
        "the accepted delete must return the instance it deletes; got "
        f"{resp['DBInstance'].get('DBInstanceIdentifier')!r}"
    )
    assert resp["DBInstance"]["DBInstanceStatus"] == "deleting", (
        "the accepted delete must report the instance as 'deleting'; got "
        f"{resp['DBInstance']['DBInstanceStatus']!r}"
    )
    snap = _poll(lambda: _snapshot(rds, snap_id), lambda s: s is not None, timeout_s=900, interval_s=15)
    assert snap is not None, (
        f"the final snapshot {snap_id} the delete promised was never created"
    )
    assert snap["DBInstanceIdentifier"] == inst_id, (
        f"the final snapshot must be attributed to {inst_id}; got "
        f"{snap['DBInstanceIdentifier']!r}"
    )
    assert snap["SnapshotType"] == "manual", (
        f"a final snapshot is SnapshotType 'manual' (it outlives the instance), got "
        f"{snap['SnapshotType']!r}"
    )
    gone = _poll(lambda: _instance(rds, inst_id), lambda i: i is None, timeout_s=1800, interval_s=20)
    assert gone is None, (
        f"the instance should be gone after the accepted delete; it is still "
        f"{gone.get('DBInstanceStatus')!r}"
    )
    snap = _poll(
        lambda: _snapshot(rds, snap_id),
        lambda s: s is not None and s.get("Status") == "available",
        timeout_s=1800,
    )
    assert snap is not None and snap["Status"] == "available", (
        "the final snapshot must survive the instance and reach 'available'; got "
        f"{snap!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
