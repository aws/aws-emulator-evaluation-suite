"""describe-clusters-empty-filter."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "describe-clusters-empty-filter"
GROUP = 'cluster_lifecycle'
SERVICES = ['rds']


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


def _unfiltered_ids(rds):
    return {c["DBClusterIdentifier"] for c in rds.describe_db_clusters()["DBClusters"]}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusters with no identifier and no filters lists a cluster while it exists and stops
    listing it once it is deleted."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-clef-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword=_make_password(),
        BackupRetentionPeriod=1,
        DBSubnetGroupName=subnet_group,
    )
    deleted = False

    def _cleanup():
        if not deleted:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"cluster {cluster_id} available",
    )

    present_ids = _unfiltered_ids(rds)
    assert cluster_id in present_ids, (
        f"expected {cluster_id} in unfiltered DescribeDBClusters, got {present_ids}"
    )

    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    deleted = True

    _poll_until(
        lambda: cluster_id in _unfiltered_ids(rds),
        lambda still_present: not still_present,
        timeout_s=300,
        interval_s=10,
        description=f"cluster {cluster_id} absent from unfiltered DescribeDBClusters",
    )

    remaining_ids = _unfiltered_ids(rds)
    assert cluster_id not in remaining_ids, (
        f"expected {cluster_id} absent from unfiltered DescribeDBClusters after delete, "
        f"got {remaining_ids}"
    )

    err = _rejection(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id))
    assert err.get("Code") == "DBClusterNotFoundFault", f"unexpected error: {err}"
    assert err.get("Message") == f"DBCluster {cluster_id} not found.", (
        f"unexpected DBClusterNotFoundFault message: {err}"
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
