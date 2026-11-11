"""delete-cluster-automated-backup-boundary."""
from __future__ import annotations

import secrets
import string
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-automated-backup-boundary"
GROUP = 'cluster_lifecycle'
SERVICES = ['rds']

ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND = "DBClusterAutomatedBackupNotFoundFault"


def _client_error(fn):
    """Call fn() and return its error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=10, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _backups_by_resource_id(rds, resource_id):
    """Unlike the DBClusterIdentifier filter, DescribeDBClusterAutomatedBackups by
    DbClusterResourceId raises DBClusterAutomatedBackupNotFoundFault instead of
    returning an empty list when nothing matches -- including transiently, while the
    backup record is being re-keyed during the source cluster's deletion."""
    try:
        return rds.describe_db_cluster_automated_backups(
            DbClusterResourceId=resource_id
        ).get("DBClusterAutomatedBackups", [])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND:
            return []
        raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBClusterAutomatedBackup deletes a retained backup of a deleted cluster, which then
    reads as gone; repeating the delete, or using an unknown DbClusterResourceId, rejects with
    DBClusterAutomatedBackupNotFoundFault."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-delclu-")
    retained_backup_id = None

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        BackupRetentionPeriod=1,
        DeletionProtection=False,
        DBSubnetGroupName=subnet_group,
    )

    def _cleanup():
        # A retained backup outlives its cluster, so delete it here if the check failed first;
        # a freshly retained backup can briefly raise InvalidDBClusterAutomatedBackupStateFault.
        if retained_backup_id is not None:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    rds.delete_db_cluster_automated_backup(DbClusterResourceId=retained_backup_id)
                    break
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code")
                    if code == ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND:
                        break
                    if code != "InvalidDBClusterAutomatedBackupStateFault":
                        raise
                    time.sleep(5)
        try:
            rds.delete_db_cluster(
                DBClusterIdentifier=cluster_id,
                SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("DBClusterNotFoundFault", "InvalidDBClusterStateFault"):
                raise

    ctx.on_cleanup(_cleanup)

    cluster = _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c.get("Status") == "available",
        timeout_s=900,
        description=f"cluster {cluster_id} available",
    )
    resource_id = cluster["DbClusterResourceId"]

    _poll_until(
        lambda: rds.describe_db_cluster_automated_backups(
            DBClusterIdentifier=cluster_id
        ).get("DBClusterAutomatedBackups", []),
        lambda backups: len(backups) > 0,
        timeout_s=180,
        description=f"automated backup record for cluster {cluster_id}",
    )

    # Retain the automated backup so it outlives the cluster.
    rds.delete_db_cluster(
        DBClusterIdentifier=cluster_id,
        SkipFinalSnapshot=True,
        DeleteAutomatedBackups=False,
    )

    retained = _poll_until(
        lambda: [
            b for b in _backups_by_resource_id(rds, resource_id) if b.get("Status") == "retained"
        ],
        lambda backups: len(backups) > 0,
        timeout_s=900,
        interval_s=15,
        description=f"automated backup for {resource_id} to reach 'retained' after cluster deletion",
    )
    assert retained[0]["DbClusterResourceId"] == resource_id, (
        f"expected retained backup for {resource_id!r}, got {retained[0]!r}"
    )
    retained_backup_id = resource_id

    # Deleting the retained automated backup succeeds.
    rds.delete_db_cluster_automated_backup(DbClusterResourceId=resource_id)
    retained_backup_id = None  # deleted -- cleanup no longer needs to touch it

    _poll_until(
        lambda: _backups_by_resource_id(rds, resource_id),
        lambda backups: len(backups) == 0,
        timeout_s=180,
        description=f"automated backup for {resource_id} gone after delete",
    )

    # Repeating the delete must fail with not-found rather than silently no-op.
    err_replay = _client_error(
        lambda: rds.delete_db_cluster_automated_backup(DbClusterResourceId=resource_id)
    )
    assert err_replay.get("Code") == ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND, (
        f"unexpected error code re-deleting a gone backup: {err_replay!r}"
    )
    assert err_replay.get("Message") == (
        f"The DB cluster automated backups weren't found for: {resource_id}"
    ), err_replay

    # A DbClusterResourceId that never existed rejects with the same code.
    bogus_resource_id = "cluster-" + uuid.uuid4().hex[:26].upper()
    err_bogus = _client_error(
        lambda: rds.delete_db_cluster_automated_backup(DbClusterResourceId=bogus_resource_id)
    )
    assert err_bogus.get("Code") == ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND, (
        f"unexpected error code: {err_bogus!r}"
    )
    assert err_bogus.get("Message") == (
        "The DB cluster automated backups weren't found for the following DB cluster resource id: "
        f"{bogus_resource_id}."
    ), err_bogus


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
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
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
