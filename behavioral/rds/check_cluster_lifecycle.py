"""cluster-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags
import secrets

CHECK = "cluster-lifecycle"
GROUP = 'cluster_lifecycle'
SERVICES = ['rds']

ERR_DB_CLUSTER_NOT_FOUND = "DBClusterNotFoundFault"

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

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBCluster -> available; DeleteDBCluster -> cluster gone.
    """
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="sim2real",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        DBSubnetGroupName=_network_db_subnet_group(ctx, rds),
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: rds.delete_db_cluster(
        DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True), "DBClusterNotFoundFault"))
    _wait_cluster_available(rds, cluster_id)

    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster["Engine"] == "aurora-mysql", (
        f"expected Engine 'aurora-mysql' on the created cluster, got {cluster['Engine']!r}"
    )

    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    deadline = time.monotonic() + 900
    code = message = None
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as _e:
            code = _e.response.get("Error", {}).get("Code")
            message = _e.response.get("Error", {}).get("Message")
            break
        time.sleep(2)
    assert code == ERR_DB_CLUSTER_NOT_FOUND, (
        f"expected {ERR_DB_CLUSTER_NOT_FOUND} after delete, got {code!r}"
    )
    assert message == f"DBCluster {cluster_id} not found.", message

    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        raise AssertionError(
            f"expected {ERR_DB_CLUSTER_NOT_FOUND} deleting an already-deleted cluster, "
            "but the call succeeded"
        )
    except ClientError as _e:
        second_delete_code = _e.response.get("Error", {}).get("Code")
        assert second_delete_code == ERR_DB_CLUSTER_NOT_FOUND, (
            f"expected {ERR_DB_CLUSTER_NOT_FOUND} deleting an already-deleted cluster, "
            f"got {second_delete_code!r}"
        )
        second_delete_message = _e.response.get("Error", {}).get("Message")
        assert second_delete_message == (
            f"The source cluster could not be found or cannot be accessed: {cluster_id}"
        ), second_delete_message


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


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
