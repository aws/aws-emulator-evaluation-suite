"""read-replica-promote."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets

CHECK = "read-replica-promote"
GROUP = 'instance_lifecycle'
SERVICES = ['rds']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _wait_available(rds, inst_id, timeout_s=900) -> None:
    """Poll until a DB instance reaches 'available'."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = rds.describe_db_instances(DBInstanceIdentifier=inst_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
        if status == "available":
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {inst_id} available not met within {timeout_s}s")


def _wait_promoted(rds, inst_id, timeout_s=1200) -> dict:
    """Poll until a DB instance is 'available' and no longer carries a replication source."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == "available" and "ReadReplicaSourceDBInstanceIdentifier" not in last:
            return last
        time.sleep(2)
    raise AssertionError(
        f"DB instance {inst_id} did not finish promoting within {timeout_s}s; last={last!r}"
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A MySQL read replica created with CreateDBInstanceReadReplica names its source in
    ReadReplicaSourceDBInstanceIdentifier, and PromoteReadReplica removes that link, leaving a
    standalone instance.
    """
    rds = ctx.client("rds")
    source_id = ctx.unique_name("sim2real-behav-inst-src-")
    rds.create_db_instance(
        DBInstanceIdentifier=source_id,
        Engine="mysql",
        EngineVersion="8.0",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="sim2real",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        BackupRetentionPeriod=1,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=source_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
    _wait_available(rds, source_id)

    replica_id = ctx.unique_name("sim2real-behav-inst-rep-")
    rds.create_db_instance_read_replica(
        DBInstanceIdentifier=replica_id,
        SourceDBInstanceIdentifier=source_id,
        DBInstanceClass="db.t3.micro",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=replica_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
    _wait_available(rds, replica_id)

    replica = rds.describe_db_instances(DBInstanceIdentifier=replica_id)["DBInstances"][0]
    assert replica["ReadReplicaSourceDBInstanceIdentifier"] == source_id, (
        f"expected replica {replica_id} to name {source_id!r} as its "
        f"ReadReplicaSourceDBInstanceIdentifier, got "
        f"{replica.get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )

    rds.promote_read_replica(DBInstanceIdentifier=replica_id)
    promoted = _wait_promoted(rds, replica_id)
    assert "ReadReplicaSourceDBInstanceIdentifier" not in promoted, (
        f"expected promotion to sever replication for {replica_id}, but it still names "
        f"{promoted.get('ReadReplicaSourceDBInstanceIdentifier')!r} as its source"
    )
    assert promoted["DBInstanceStatus"] == "available", (
        f"expected {replica_id} to be 'available' after promotion, got "
        f"{promoted['DBInstanceStatus']!r}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it.

    The 1500 s window fits this suite's 1800 s teardown budget.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
