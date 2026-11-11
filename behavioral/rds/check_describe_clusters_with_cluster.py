"""describe-clusters-with-cluster."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-clusters-with-cluster"
GROUP = 'cluster_lifecycle'
SERVICES = ['rds']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _make_password():
    return "Sim2Real1" + uuid.uuid4().hex[:8] + "!"


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _cluster(rds, cid):
    try:
        clusters = rds.describe_db_clusters(DBClusterIdentifier=cid).get("DBClusters", [])
        return clusters[0] if clusters else None
    except ClientError:
        return None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusters: a real Aurora cluster is listed both unfiltered and by
    DBClusterIdentifier once available. Error boundary: an unknown DBClusterIdentifier rejects with
    DBClusterNotFoundFault.
    """
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword=_make_password(),
        BackupRetentionPeriod=1,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    def _cleanup_delete():
        try:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DBClusterNotFoundFault":
                raise

    ctx.on_cleanup(_cleanup_delete)
    cluster = _poll_until(
        lambda: _cluster(rds, cluster_id),
        lambda c: c is not None and c.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"cluster {cluster_id} available",
    )
    assert cluster["DBClusterIdentifier"] == cluster_id
    assert cluster["Engine"] == "aurora-mysql"

    all_ids = {c["DBClusterIdentifier"] for c in rds.describe_db_clusters()["DBClusters"]}
    assert cluster_id in all_ids

    bogus_cluster = ctx.unique_name("sim2real-behav-clu-missing-")
    err = _rejection(lambda: rds.describe_db_clusters(DBClusterIdentifier=bogus_cluster))
    assert err.get("Code") == "DBClusterNotFoundFault", f"unexpected error: {err}"
    assert err.get("Message") == f"DBCluster {bogus_cluster} not found.", (
        f"unexpected DBClusterNotFoundFault message: {err}"
    )

    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    _poll_until(
        lambda: _cluster(rds, cluster_id),
        lambda c: c is None,
        timeout_s=900,
        interval_s=10,
        description=f"cluster {cluster_id} deleted",
    )
    gone = _rejection(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id))
    assert gone.get("Code") == "DBClusterNotFoundFault", f"unexpected error after delete: {gone}"
    assert gone.get("Message") == f"DBCluster {cluster_id} not found.", (
        f"unexpected DBClusterNotFoundFault message after delete: {gone}"
    )

    mutate = _rejection(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    assert mutate.get("Code") == "DBClusterNotFoundFault", (
        f"a mutation on the deleted cluster must also fail not-found, got {mutate}"
    )
    assert mutate.get("Message") == (
        f"The source cluster could not be found or cannot be accessed: {cluster_id}"
    ), f"unexpected DBClusterNotFoundFault message for DeleteDBCluster: {mutate}"


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
