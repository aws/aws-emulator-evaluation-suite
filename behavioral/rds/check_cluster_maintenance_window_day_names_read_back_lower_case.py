"""cluster-maintenance-window-day-names-read-back-lower-case."""

from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-maintenance-window-day-names-read-back-lower-case"
GROUP = "maintenance_windows"
SERVICES = ["rds"]

_SENT_MAINTENANCE_WINDOW = "Mon:00:00-Mon:03:00"
_STORED_MAINTENANCE_WINDOW = "mon:00:00-mon:03:00"
_BACKUP_WINDOW = "07:00-07:30"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBCluster stores a capitalised PreferredMaintenanceWindow with lower-case day names.

    The create answer and DescribeDBClusters both return it so, next to the backup window.
    """
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-mwcase-")
    subnet_group = _network_db_subnet_group(ctx, rds)

    created = rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=1,
        PreferredBackupWindow=_BACKUP_WINDOW,
        PreferredMaintenanceWindow=_SENT_MAINTENANCE_WINDOW,
        DeletionProtection=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["DBCluster"]
    ctx.on_cleanup(lambda: _delete_cluster(rds, cluster_id))

    assert created["PreferredMaintenanceWindow"] == _STORED_MAINTENANCE_WINDOW, (
        f"CreateDBCluster answered {created['PreferredMaintenanceWindow']!r} "
        f"for {_SENT_MAINTENANCE_WINDOW!r}, expected {_STORED_MAINTENANCE_WINDOW!r}"
    )
    assert created["PreferredBackupWindow"] == _BACKUP_WINDOW, (
        f"CreateDBCluster answered PreferredBackupWindow {created['PreferredBackupWindow']!r}"
    )

    described = _wait_cluster_available(ctx, rds, cluster_id)
    assert described["PreferredMaintenanceWindow"] == _STORED_MAINTENANCE_WINDOW, (
        f"DescribeDBClusters returned PreferredMaintenanceWindow "
        f"{described['PreferredMaintenanceWindow']!r}, expected {_STORED_MAINTENANCE_WINDOW!r}"
    )
    assert described["PreferredBackupWindow"] == _BACKUP_WINDOW, (
        f"DescribeDBClusters returned PreferredBackupWindow {described['PreferredBackupWindow']!r}"
    )
    assert described["BackupRetentionPeriod"] == 1, (
        f"DescribeDBClusters returned BackupRetentionPeriod {described['BackupRetentionPeriod']!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_cluster_available(ctx, rds, cluster_id, poll_s=5.0) -> dict:
    deadline = time.monotonic() + min(900.0, max(60.0, (ctx.time_left() or 1200.0) - 300.0))
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == "available":
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached 'available', last status {last and last['Status']!r}"
    )


def _delete_cluster(rds, cluster_id, timeout_s=900.0, poll_s=5.0) -> None:
    """Delete the cluster once it accepts the delete, then poll until it is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBClusterNotFoundFault":
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(poll_s)
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(poll_s)
    raise AssertionError(f"cluster {cluster_id} was still present {timeout_s}s after its delete")


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_subnet_group(client, name))
    return name


def _delete_subnet_group(client, name, timeout_s=900.0, poll_s=5.0) -> None:
    """Delete a subnet group, retrying while a cluster that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.delete_db_subnet_group(DBSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "DBSubnetGroupNotFoundFault":
                return
            if code != "InvalidDBSubnetGroupStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(poll_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
