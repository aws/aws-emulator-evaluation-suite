"""read-replica-promote-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "read-replica-promote-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An oracle-ee read replica is replicating from its primary, SwitchoverReadReplica exchanges the
    primary and replica roles, and PromoteReadReplica turns the new replica into a standalone
    instance."""

    rds = ctx.client("rds")
    sng = _subnet_group(ctx)
    password = "Sim2RealBehav1!"
    engine_version = _pick_ee_engine_version(rds)

    primary_id = ctx.unique_name("sim2real-oraprim-")
    rds.create_db_instance(
        DBInstanceIdentifier=primary_id,
        DBInstanceClass="db.m5.large",
        Engine="oracle-ee",
        EngineVersion=engine_version,
        LicenseModel="bring-your-own-license",
        MasterUsername="admin",
        MasterUserPassword=password,
        AllocatedStorage=20,
        StorageType="gp3",
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, primary_id))

    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=primary_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=2400, interval_s=30, desc="Oracle EE primary available",
    )

    replica_id = ctx.unique_name("sim2real-orastby-")
    rds.create_db_instance_read_replica(
        DBInstanceIdentifier=replica_id,
        SourceDBInstanceIdentifier=primary_id,
        DBInstanceClass="db.m5.large",
        ReplicaMode="mounted",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Issue both deletes before waiting on either: ctx.on_cleanup runs its callbacks with a much
    # tighter budget than two sequential RDS instance deletions take (each easily minutes), so a
    # naive delete-then-wait-per-instance leaves the second instance's delete never even issued.
    # Deleting both concurrently and only then waiting turns the total teardown wait into
    # roughly max(replica, primary) instead of their sum.
    ctx.on_cleanup(lambda: _delete_both_instances(rds, replica_id, primary_id))

    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=replica_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available" and not i.get("PendingModifiedValues"),
        timeout_s=2400, interval_s=30, desc="Data Guard standby available",
    )

    # Automatic backups are OFF by default on a read replica (CreateDBInstanceReadReplica has no
    # BackupRetentionPeriod parameter at all), and SwitchoverReadReplica rejects a replica with
    # BackupRetentionPeriod == 0 as "not ready for a role transition".
    # It must be set after creation via ModifyDBInstance.
    rds.modify_db_instance(
        DBInstanceIdentifier=replica_id, BackupRetentionPeriod=1, ApplyImmediately=True,
    )
    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=replica_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available"
        and not i.get("PendingModifiedValues")
        and i["BackupRetentionPeriod"] > 0,
        timeout_s=600, interval_s=15, desc="standby backup retention period applied",
    )
    replica_before = rds.describe_db_instances(DBInstanceIdentifier=replica_id)["DBInstances"][0]
    assert replica_before["ReadReplicaSourceDBInstanceIdentifier"] == primary_id, (
        f"expected replica {replica_id!r} to report source {primary_id!r}, "
        f"got {replica_before.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )
    assert replica_before["StatusInfos"][0]["Status"] == "replicating", (
        f"expected replica {replica_id!r} StatusInfos[0].Status == 'replicating', "
        f"got {replica_before['StatusInfos'][0]!r}"
    )

    rds.switchover_read_replica(DBInstanceIdentifier=replica_id)

    # After switchover, roles exchange: the former replica becomes the primary (no source
    # identifier) and the former primary becomes the standby (now carries a source identifier).
    replica_after = _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=replica_id)["DBInstances"][0],
        lambda i: "ReadReplicaSourceDBInstanceIdentifier" not in i and i["DBInstanceStatus"] == "available",
        timeout_s=900, interval_s=15, desc="switchover promotes former standby to primary",
    )
    # PromoteReadReplica requires DBInstanceStatus == "available"; right after switchover the
    # former primary can still be transiently settling into its new standby role even once it
    # already carries the new source identifier, and a promote issued then fails with "DB
    # Instance is not in available state".
    primary_after = _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=primary_id)["DBInstances"][0],
        lambda i: i.get("ReadReplicaSourceDBInstanceIdentifier") == replica_id
        and i["DBInstanceStatus"] == "available"
        and not i.get("PendingModifiedValues"),
        timeout_s=900, interval_s=15, desc="former primary becomes available standby of new primary",
    )
    assert "ReadReplicaSourceDBInstanceIdentifier" not in replica_after, (
        f"expected former standby {replica_id!r} to carry no source identifier after switchover, "
        f"got {replica_after.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )
    assert primary_after["ReadReplicaSourceDBInstanceIdentifier"] == replica_id, (
        f"expected former primary {primary_id!r} to now report source {replica_id!r}, "
        f"got {primary_after.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )

    rds.promote_read_replica(DBInstanceIdentifier=primary_id)

    promoted = _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=primary_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available" and "ReadReplicaSourceDBInstanceIdentifier" not in i,
        timeout_s=900, interval_s=15, desc="former standby promoted to standalone",
    )
    assert "ReadReplicaSourceDBInstanceIdentifier" not in promoted, (
        f"expected {primary_id!r} to carry no source identifier after PromoteReadReplica, "
        f"got {promoted.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )


def _wait_until(probe, predicate, timeout_s, interval_s=20, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last}")
        time.sleep(interval_s)


def _wait_gone(probe, not_found_codes, timeout_s, interval_s=20, desc="deletion"):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            probe()
        except ClientError as e:
            if e.response["Error"]["Code"] in not_found_codes:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}")
        time.sleep(interval_s)


def _subnet_group(ctx, name_prefix="sim2real-sng-"):

    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build a DB subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span enough AZs for a DB subnet group")
    name = ctx.unique_name(name_prefix)
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids[:3],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _pick_ee_engine_version(rds, min_major: int = 19) -> str:
    """Oracle Data Guard switchover requires Oracle Database 19c or higher; the account-wide
    DEFAULT oracle-ee version is the most commonly requested (warmest, fastest-provisioning)
    version, which matters most for the slowest engine RDS offers."""
    versions = rds.describe_db_engine_versions(Engine="oracle-ee", DefaultOnly=True)["DBEngineVersions"]
    default_version = versions[0]["EngineVersion"] if versions else None
    if default_version and int(default_version.split(".")[0]) >= min_major:
        return default_version

    versions = [
        v["EngineVersion"] for v in rds.describe_db_engine_versions(Engine="oracle-ee")["DBEngineVersions"]
        if v.get("Status", "available") == "available" and int(v["EngineVersion"].split(".")[0]) >= min_major
    ]
    assert versions, f"no oracle-ee engine version >= {min_major}c available in this account/region"
    return sorted(versions)[-1]


def _delete_instance(rds, inst_id):
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id),
        {"DBInstanceNotFound"}, timeout_s=1800, interval_s=20, desc=f"instance {inst_id} deleted",
    )


def _issue_delete(rds, inst_id):
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("DBInstanceNotFound", "InvalidDBInstanceState"):
            raise


def _delete_both_instances(rds, first_id, second_id):
    _issue_delete(rds, first_id)
    _issue_delete(rds, second_id)
    _wait_gone(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=first_id),
        {"DBInstanceNotFound"}, timeout_s=1800, interval_s=20, desc=f"instance {first_id} deleted",
    )
    _wait_gone(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=second_id),
        {"DBInstanceNotFound"}, timeout_s=1800, interval_s=20, desc=f"instance {second_id} deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
