"""create-db-backup-completes-and-lists."""
from __future__ import annotations

import secrets
import time

from behavioral_harness import tags

CHECK = "create-db-backup-completes-and-lists"
GROUP = "state"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDbBackup transitions IN_PROGRESS -> COMPLETED against a real AVAILABLE
    instance, and the completed backup shows up in ListDbBackups for that instance."""
    net = _ensure_network(ctx)
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-backupsrc-")
    created = influx.create_db_instance(
        name=name,
        password=secrets.token_hex(12),
        dbInstanceType="db.influx.medium",
        vpcSubnetIds=net["subnet_ids"],
        vpcSecurityGroupIds=[net["security_group_id"]],
        allocatedStorage=20,
        dbStorageType="InfluxIOIncludedT1",
        deploymentType="SINGLE_AZ",
        tags={"sim2real-check": CHECK},
    )
    instance_id = created["id"]
    ctx.on_cleanup(lambda: _delete_instance_if_present(ctx, instance_id))

    available = _poll_until(
        lambda: influx.get_db_instance(identifier=instance_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=2400,
        interval_s=30,
    )
    assert available["status"] == "AVAILABLE", (
        f"expected source DB instance AVAILABLE, got {available['status']!r}"
    )

    backup_name = ctx.unique_name("sim2real-backup-")
    backup = influx.create_db_backup(
        name=backup_name,
        dbResourceId=instance_id,
        retentionDays=1,
        tags={"sim2real-check": CHECK},
    )
    backup_id = backup["id"]
    assert backup["status"] == "IN_PROGRESS", (
        f"expected freshly-created backup status IN_PROGRESS, got {backup['status']!r}"
    )
    assert backup["type"] == "ON_DEMAND", f"expected backup type ON_DEMAND, got {backup['type']!r}"
    ctx.on_cleanup(lambda: _delete_backup_if_present(ctx, backup_id))

    final_backup = _poll_until(
        lambda: influx.get_db_backup(identifier=backup_id),
        lambda r: r["status"] in ("COMPLETED", "FAILED"),
        timeout_s=1800,
        interval_s=20,
    )
    assert final_backup["status"] == "COMPLETED", (
        f"expected backup to reach COMPLETED, got {final_backup['status']!r}"
    )
    assert final_backup["expiresAfter"], (
        f"expected a non-empty expiresAfter on a completed backup, got {final_backup['expiresAfter']!r}"
    )

    items = influx.list_db_backups(dbResourceId=instance_id)["items"]
    assert any(i["id"] == backup_id for i in items), (
        f"backup {backup_id!r} not found in ListDbBackups items: {items!r}"
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
            {
                "ResourceType": "security-group",
                "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
            }
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
