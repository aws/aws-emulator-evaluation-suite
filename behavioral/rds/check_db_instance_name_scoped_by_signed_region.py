"""db-instance-name-scoped-by-signed-region."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-instance-name-scoped-by-signed-region"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

_EAST = "us-east-1"

ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"


def _default_engine_version(rds, engine):
    try:
        versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True).get(
            "DBEngineVersions", []
        )
    except ClientError:
        return None
    return versions[0]["EngineVersion"] if versions else None


def _instance(rds, inst_id):
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_DB_INSTANCE_NOT_FOUND:
            return None
        raise


def _delete_and_wait(rds, inst_id, timeout_s=1200.0):
    """Delete an instance with no final snapshot and wait until it is gone, so its subnet group
    can go next; a prior delete in the check body may already have removed it."""
    deadline = time.monotonic() + timeout_s
    while (inst := _instance(rds, inst_id)) is not None:
        if inst.get("DBInstanceStatus") != "deleting":
            # Re-issued until accepted: an instance still modifying refuses the delete.
            try:
                rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in (ERR_DB_INSTANCE_NOT_FOUND, "InvalidDBInstanceState"):
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"instance {inst_id} still {inst.get('DBInstanceStatus')!r} after {timeout_s}s")
        time.sleep(15)


def _subnet_group(ctx, rds, region):
    """A DB subnet group over *region*'s shared network, deleted after the instances in it."""
    name = ctx.unique_name("sim2real-behav-rsng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=ctx.network(region).subnet_ids,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _poll_pair_available(rds_a, id_a, rds_b, id_b, *, timeout_s=1500, interval_s=15):
    """Poll two regional instances round-robin, so they provision concurrently rather than
    waiting out one region's deadline before starting the other's."""
    deadline = time.monotonic() + timeout_s
    inst_a = inst_b = None
    while time.monotonic() < deadline:
        if inst_a is None or inst_a.get("DBInstanceStatus") != "available":
            inst_a = _instance(rds_a, id_a)
        if inst_b is None or inst_b.get("DBInstanceStatus") != "available":
            inst_b = _instance(rds_b, id_b)
        a_ready = inst_a is not None and inst_a.get("DBInstanceStatus") == "available"
        b_ready = inst_b is not None and inst_b.get("DBInstanceStatus") == "available"
        if a_ready and b_ready:
            return inst_a, inst_b
        time.sleep(interval_s)
    raise AssertionError(
        f"instances did not both reach 'available' within {timeout_s}s: "
        f"a={inst_a.get('DBInstanceStatus') if inst_a else None!r} "
        f"b={inst_b.get('DBInstanceStatus') if inst_b else None!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One DBInstanceIdentifier in two regions names two independent instances: distinct ARNs with their
    own region, a modify in one leaves the other unchanged, and deleting one leaves the other
    describable."""
    inst_id = ctx.unique_name("sim2real-behav-rinst-")

    rds_east = ctx.client("rds", region=_EAST)
    rds_west = ctx.client("rds", region=ctx.region)

    version_east = _default_engine_version(rds_east, "postgres")
    version_west = _default_engine_version(rds_west, "postgres")

    create_kwargs = dict(
        DBInstanceIdentifier=inst_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword=secrets.token_urlsafe(18),
        BackupRetentionPeriod=0,
        MultiAZ=False,
        PubliclyAccessible=False,
        StorageType="gp2",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )

    # Each region's instance sits in that region's shared network.
    east_sng = _subnet_group(ctx, rds_east, _EAST)
    west_sng = _subnet_group(ctx, rds_west, ctx.region)
    east_create = rds_east.create_db_instance(
        **{**create_kwargs, "DBSubnetGroupName": east_sng, **({"EngineVersion": version_east} if version_east else {})}
    )
    ctx.on_cleanup(lambda: _delete_and_wait(rds_east, inst_id))
    west_create = rds_west.create_db_instance(
        **{**create_kwargs, "DBSubnetGroupName": west_sng, **({"EngineVersion": version_west} if version_west else {})}
    )
    ctx.on_cleanup(lambda: _delete_and_wait(rds_west, inst_id))

    east_arn = east_create["DBInstance"]["DBInstanceArn"]
    west_arn = west_create["DBInstance"]["DBInstanceArn"]
    assert f":rds:{_EAST}:" in east_arn, f"east instance ARN {east_arn!r} does not carry {_EAST!r}"
    assert f":rds:{ctx.region}:" in west_arn, f"west instance ARN {west_arn!r} does not carry {ctx.region!r}"
    assert east_arn != west_arn, (
        f"same-identifier instances in two regions produced the SAME ARN {east_arn!r} -- "
        "the identifier is not actually region-scoped"
    )

    east_inst, west_inst = _poll_pair_available(rds_east, inst_id, rds_west, inst_id)
    assert east_inst["DBInstanceArn"] == east_arn, east_inst["DBInstanceArn"]
    assert west_inst["DBInstanceArn"] == west_arn, west_inst["DBInstanceArn"]

    rds_east.modify_db_instance(
        DBInstanceIdentifier=inst_id, MasterUserPassword=secrets.token_urlsafe(18), ApplyImmediately=True
    )
    west_after_east_modify = rds_west.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    assert west_after_east_modify["DBInstanceArn"] == west_arn, (
        "west instance ARN changed after a modify issued against the east-signed client: "
        f"{west_after_east_modify['DBInstanceArn']!r} != {west_arn!r}"
    )
    assert west_after_east_modify["DBInstanceStatus"] in ("available", "modifying"), (
        f"west instance entered status {west_after_east_modify['DBInstanceStatus']!r} as a side "
        "effect of a modify issued against the east-signed client -- the two regions are not isolated"
    )

    rds_east.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    left = ctx.time_left()
    deadline = time.monotonic() + (1500 if left is None else min(1500, left))
    east_gone_code = east_gone_message = None
    while time.monotonic() < deadline:
        try:
            rds_east.describe_db_instances(DBInstanceIdentifier=inst_id)
        except ClientError as exc:
            east_gone_code = exc.response.get("Error", {}).get("Code")
            east_gone_message = exc.response.get("Error", {}).get("Message")
            break
        time.sleep(2)
    assert east_gone_code == ERR_DB_INSTANCE_NOT_FOUND, (
        f"east instance did not fault {ERR_DB_INSTANCE_NOT_FOUND!r} after delete; got {east_gone_code!r}"
    )
    assert east_gone_message == f"DBInstance {inst_id} not found.", east_gone_message

    west_after_east_delete = rds_west.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    assert west_after_east_delete["DBInstanceArn"] == west_arn, (
        "west instance vanished or changed identity after the SAME identifier was deleted in "
        f"east: {west_after_east_delete!r}"
    )
    assert west_after_east_delete["DBInstanceStatus"] in ("available", "modifying"), (
        f"west instance entered status {west_after_east_delete['DBInstanceStatus']!r} as a side "
        "effect of deleting the same-named instance in east -- the two regions are not isolated"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
