"""restore-from-db-backup-creates-available-instance."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "restore-from-db-backup-creates-available-instance"
GROUP = "state"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreFromDbBackup starts in RESTORING and produces a brand-new DB instance that
    itself reaches AVAILABLE, independent of the source instance/backup."""
    net = _ensure_network(ctx)
    influx = ctx.client("timestream-influxdb")

    source_name = ctx.unique_name("sim2real-restoresrc-")
    source = influx.create_db_instance(
        name=source_name,
        password=secrets.token_hex(12),
        dbInstanceType="db.influx.medium",
        vpcSubnetIds=net["subnet_ids"],
        vpcSecurityGroupIds=[net["security_group_id"]],
        allocatedStorage=20,
        dbStorageType="InfluxIOIncludedT1",
        deploymentType="SINGLE_AZ",
        tags={"sim2real": CHECK},
    )
    source_id = source["id"]
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, source_id))

    source_available = _poll_until(
        lambda: influx.get_db_instance(identifier=source_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert source_available["status"] == "AVAILABLE", (
        f"expected source instance {source_id} to reach AVAILABLE, got {source_available['status']!r}"
    )

    backup_name = ctx.unique_name("sim2real-restorebkp-")
    backup = influx.create_db_backup(
        name=backup_name, dbResourceId=source_id, retentionDays=1, tags={"sim2real": CHECK}
    )
    backup_id = backup["id"]
    ctx.on_cleanup(lambda: _delete_backup_if_present(ctx, backup_id))
    completed_backup = _poll_until(
        lambda: influx.get_db_backup(identifier=backup_id),
        lambda r: r["status"] in ("COMPLETED", "FAILED"),
        timeout_s=1800,
        interval_s=20,
    )
    assert completed_backup["status"] == "COMPLETED", (
        f"expected backup {backup_id} to reach COMPLETED, got {completed_backup['status']!r}"
    )

    restored_name = ctx.unique_name("sim2real-restored-")
    restore = influx.restore_from_db_backup(
        name=restored_name, dbBackupId=backup_id, tags={"sim2real": CHECK}
    )
    restored_id = restore["restoredDbResourceId"]
    assert restore["restoreStatus"] == "RESTORING", (
        f"expected RestoreFromDbBackup's own response to report restoreStatus=RESTORING, "
        f"got {restore['restoreStatus']!r}"
    )
    # The Smithy model documents this field as the ResourceType enum (DB_INSTANCE/DB_CLUSTER),
    # but AWS returns the lowercase-hyphenated wire value "db-instance".
    assert restore["resourceType"] == "db-instance", (
        f"expected RestoreFromDbBackup to restore a db-instance, got resourceType={restore['resourceType']!r}"
    )
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, restored_id))

    restored_final = _poll_until(
        lambda: influx.get_db_instance(identifier=restored_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert restored_final["status"] == "AVAILABLE", (
        f"expected restored instance {restored_id} to reach AVAILABLE, got {restored_final['status']!r}"
    )
    assert restored_final["name"] == restored_name, (
        f"expected restored instance name {restored_name!r}, got {restored_final['name']!r}"
    )
    # The restored instance is a distinct resource from the source.
    assert restored_final["id"] != source_id, (
        f"expected restore to produce a new resource id distinct from source {source_id!r}, "
        f"got the same id back"
    )


def _delete_instance_if_present(ctx, instance_id):
    from botocore.exceptions import ClientError

    influx = ctx.client("timestream-influxdb")
    try:
        influx.delete_db_instance(identifier=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_backup_if_present(ctx, backup_id):
    from botocore.exceptions import ClientError

    influx = ctx.client("timestream-influxdb")
    try:
        influx.delete_db_backup(identifier=backup_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to provision Timestream for InfluxDB "
            "networking prerequisites (would need a custom VPC/subnet/route-table setup)"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if len(subnets) < 2:
        raise AssertionError("shared network does not have at least 2 shared-network subnet")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sg_name = ctx.unique_name("sim2real-influxdb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real timestream-influxdb behavioral check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "security_group_id": sg_id}


def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
