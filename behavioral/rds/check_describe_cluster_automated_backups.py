"""describe-cluster-automated-backups."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-cluster-automated-backups"
GROUP = 'cluster_lifecycle'
SERVICES = ['rds']

ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND = "DBClusterAutomatedBackupNotFoundFault"


def _error_code(fn):
    """Call fn() and return its botocore error code and message; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"expected {ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND}, but the call SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=600, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusterAutomatedBackups for an unknown cluster id fails
    DBClusterAutomatedBackupNotFoundFault; an available Aurora cluster lists its backup record.
    """
    rds = ctx.client("rds")
    bogus_cluster = ctx.unique_name("sim2real-behav-clu-missing-")
    code, message = _error_code(
        lambda: rds.describe_db_cluster_automated_backups(DBClusterIdentifier=bogus_cluster)
    )
    assert code == ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND, (
        f"expected {ERR_CLUSTER_AUTOMATED_BACKUP_NOT_FOUND}, got {code}"
    )
    assert message == f"DBClusterAutomatedBackup for DBCluster {bogus_cluster} not found.", message

    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2Real#Pass99",
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c.get("Status") == "available",
        timeout_s=600,
        interval_s=5,
        description=f"cluster {cluster_id} available",
    )

    backups = _poll_until(
        lambda: rds.describe_db_cluster_automated_backups(
            DBClusterIdentifier=cluster_id
        ).get("DBClusterAutomatedBackups", []),
        lambda b: len(b) > 0,
        timeout_s=180,
        interval_s=5,
        description=f"automated backup record for cluster {cluster_id}",
    )
    assert backups[0]["DBClusterIdentifier"] == cluster_id, (
        f"expected automated backup for {cluster_id}, got {backups[0]!r}"
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
