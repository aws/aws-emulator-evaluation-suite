"""describe-nonexistent-cluster."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-cluster"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_CLUSTER_NOT_FOUND = "DBClusterNotFoundFault"


def _wait_cluster_available(rds, cluster_id, timeout_s=900) -> None:
    """Poll until a DB cluster reaches 'available' -- delete is rejected before then."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
            "DBClusters"
        ][0]["Status"]
        if status == "available":
            return
        time.sleep(2)
    raise AssertionError(f"DB cluster {cluster_id} did not reach available within {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDBClusters on a well-formed but never-created identifier raises
    DBClusterNotFound -- proven against a real cluster of the same shape, so the rejection is
    about existence and not about a broken or unauthorized DescribeDBClusters call."""
    rds = ctx.client("rds")
    real_id = ctx.unique_name("sim2real-behav-clus-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=real_id,
        Engine="aurora-mysql",
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(rds, real_id))

    # Positive control: the identical call, against a cluster that really exists, succeeds.
    found = rds.describe_db_clusters(DBClusterIdentifier=real_id)["DBClusters"]
    assert len(found) == 1 and found[0]["DBClusterIdentifier"] == real_id, (
        f"expected the just-created cluster {real_id!r} to describe, got {found!r}"
    )

    # Perturb the real identifier rather than fabricating one out of thin air, so the negative
    # differs from the positive control by existence alone -- not by shape or naming scope.
    ghost = real_id + "-ghost"
    try:
        rds.describe_db_clusters(DBClusterIdentifier=ghost)
        code = message = None
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_DB_CLUSTER_NOT_FOUND, f"expected {ERR_DB_CLUSTER_NOT_FOUND}, got {code!r}"
    assert message == f"DBCluster {ghost} not found.", message


def _delete_cluster(rds, cluster_id) -> None:
    _wait_cluster_available(rds, cluster_id)
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)


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
