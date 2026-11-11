"""create-read-replica-cross-engine-mismatch-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-read-replica-cross-engine-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASS = "Sim2RealPwd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """CreateDBInstanceReadReplica from an Aurora cluster member is rejected with
    InvalidParameterCombination and creates no replica, while a postgres source gets an available
    replica of itself."""
    rds = ctx.client("rds")

    # --- Negative: source is an Aurora cluster member instance. ---
    cluster_id = ctx.unique_name("sim2real-auresrc-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBSubnetGroupName=subnet_group,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername=_ADMIN_USER,
        MasterUserPassword=_ADMIN_PASS,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))
    _wait_for_cluster_status(rds, cluster_id, "available", timeout_s=600)

    aurora_instance_id = ctx.unique_name("sim2real-aurinst-")
    rds.create_db_instance(
        DBInstanceIdentifier=aurora_instance_id,
        DBInstanceClass="db.t3.medium",
        Engine="aurora-mysql",
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, aurora_instance_id))
    _wait_for_instance_status(rds, aurora_instance_id, "available", timeout_s=1200)

    replica_id = ctx.unique_name("sim2real-badreplica-")
    ctx.on_cleanup(lambda: _delete_instance(rds, replica_id))  # safety net if creation was not rejected
    code, message = _error(
        lambda: rds.create_db_instance_read_replica(
            DBInstanceIdentifier=replica_id,
            SourceDBInstanceIdentifier=aurora_instance_id,
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
    )
    assert code == "InvalidParameterCombination", f"unexpected error code: {code!r}"
    expected = "Cannot create a read replica for a DB Instance that belongs to a DB Cluster"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=replica_id)
    )
    assert not_found_code == "DBInstanceNotFound", (
        f"replica {replica_id} unexpectedly exists after a rejected create: {not_found_code!r}"
    )
    expected_nf = f"DBInstance {replica_id} not found."
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

    # --- Positive control: a standard (non-Aurora) source accepts the same call. ---
    source_id = ctx.unique_name("sim2real-pgsrc-")
    rds.create_db_instance(
        DBInstanceIdentifier=source_id,
        DBSubnetGroupName=subnet_group,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername=_ADMIN_USER,
        MasterUserPassword=_ADMIN_PASS,
        AllocatedStorage=20,
        BackupRetentionPeriod=1,  # read replicas require backups enabled on the source
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, source_id))
    _wait_for_instance_status(rds, source_id, "available", timeout_s=900)

    good_replica_id = ctx.unique_name("sim2real-goodreplica-")
    resp = rds.create_db_instance_read_replica(
        DBInstanceIdentifier=good_replica_id,
        SourceDBInstanceIdentifier=source_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, good_replica_id))
    assert resp["DBInstance"]["ReadReplicaSourceDBInstanceIdentifier"] == source_id, (
        f"create response source mismatch: expected {source_id!r}, "
        f"got {resp['DBInstance'].get('ReadReplicaSourceDBInstanceIdentifier')!r}"
    )
    assert resp["DBInstance"]["DBInstanceStatus"] in ("creating", "available"), (
        f"unexpected status on create response: {resp['DBInstance'].get('DBInstanceStatus')!r}"
    )

    # --- The terminal read is independent of the mutating call. ---
    _wait_for_instance_status(rds, good_replica_id, "available", timeout_s=1200)
    settled = _describe_instance(rds, good_replica_id)
    assert settled["ReadReplicaSourceDBInstanceIdentifier"] == source_id, (
        f"independent read shows source {settled.get('ReadReplicaSourceDBInstanceIdentifier')!r}, "
        f"expected {source_id!r}"
    )
    assert settled["DBInstanceStatus"] == "available", (
        f"independent read shows status {settled.get('DBInstanceStatus')!r}, expected 'available'"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _instance_status(rds: Any, db_id: str) -> str | None:
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]["DBInstanceStatus"]
    except ClientError:
        return None


def _describe_instance(rds: Any, db_id: str) -> dict[str, Any]:
    return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]


def _describe_cluster(rds: Any, cluster_id: str) -> dict[str, Any]:
    return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]


def _wait_for_instance_status(rds: Any, db_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = _describe_instance(rds, db_id)
        if inst["DBInstanceStatus"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {db_id} never reached status={status!r} in {timeout_s}s")


def _wait_for_cluster_status(rds: Any, cluster_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = _describe_cluster(rds, cluster_id)
        if cluster["Status"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached status={status!r} in {timeout_s}s")


def _delete_instance(rds: Any, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBInstanceNotFound", "DBInstanceNotFoundFault"):
            raise


def _delete_cluster(rds: Any, cluster_id: str) -> None:
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise


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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
