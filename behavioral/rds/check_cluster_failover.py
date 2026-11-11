"""cluster-failover."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-failover"
GROUP = 'cluster_lifecycle'
SERVICES = ['rds']

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    {"Key": "sim2real", "Value": "cluster-failover"},
]

def _delete_instance_retrying(rds, inst_id, *, deadline_s=900) -> None:
    """Delete the instance; gone counts as deleted, InvalidDBInstanceState (a status transition
    in progress) is retried every 2 s to the deadline, and every other error raises."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True,
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBInstanceNotFound":
                return
            if code != "InvalidDBInstanceState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)

def _delete_cluster_retrying(rds, cluster_id, *, deadline_s=900) -> None:
    """Delete the cluster; Aurora refuses with InvalidDBClusterStateFault until every member has
    finished deleting, so that is retried every 2 s to the deadline; gone counts as deleted and
    every other error raises."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBClusterNotFoundFault":
                return
            if code != "InvalidDBClusterStateFault" or time.monotonic() >= deadline:
                raise
            time.sleep(2)

def _wait_cluster_available(rds, cluster_id, timeout_s=900) -> None:
    """Poll until a DB cluster reaches 'available'."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
            "DBClusters"
        ][0]["Status"]
        if status == "available":
            return
        time.sleep(2)
    raise AssertionError(f"DB cluster {cluster_id} available not met within {timeout_s}s")

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

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FailoverDBCluster to the reader makes it the cluster's writer and the old writer a reader,
    as DescribeDBClusters reports once the cluster is available again."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        Tags=_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster_retrying(rds, cluster_id))
    _wait_cluster_available(rds, cluster_id)

    writer_id = ctx.unique_name("sim2real-behav-inst-writer-")
    rds.create_db_instance(
        DBInstanceIdentifier=writer_id,
        DBInstanceClass="db.t3.medium",
        Engine="aurora-mysql",
        DBClusterIdentifier=cluster_id,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_retrying(rds, writer_id))
    _wait_available(rds, writer_id)

    reader_id = ctx.unique_name("sim2real-behav-inst-reader-")
    rds.create_db_instance(
        DBInstanceIdentifier=reader_id,
        DBInstanceClass="db.t3.medium",
        Engine="aurora-mysql",
        DBClusterIdentifier=cluster_id,
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_instance_retrying(rds, reader_id))
    _wait_available(rds, reader_id)

    rds.failover_db_cluster(
        DBClusterIdentifier=cluster_id, TargetDBInstanceIdentifier=reader_id
    )

    deadline = time.monotonic() + 600
    members: dict = {}
    while time.monotonic() < deadline:
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if cluster.get("Status") == "available":
            members = {
                m["DBInstanceIdentifier"]: m["IsClusterWriter"]
                for m in cluster["DBClusterMembers"]
            }
            if members.get(reader_id) is True:
                break
        time.sleep(2)
    else:
        raise AssertionError("cluster failover did not complete in time")
    assert members[reader_id] is True, "target instance did not become writer"
    assert members[writer_id] is False, "old writer still reports as writer"


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
