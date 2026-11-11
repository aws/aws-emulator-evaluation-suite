"""delete-cluster-with-members."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "delete-cluster-with-members"
GROUP = 'cluster_lifecycle'
SERVICES = ['rds']

ERR_INVALID_DB_CLUSTER_STATE = "InvalidDBClusterStateFault"

def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _not_found(fn, code):
    """True once fn() fails with the given not-found code; False while the resource still reads."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == code:
            return True
        raise
    return False

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

def _wait_instance_gone(rds, inst_id, timeout_s=1200) -> None:
    """Poll until a DB instance's independent read reports not-found."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _not_found(lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id), "DBInstanceNotFound"):
            return
        time.sleep(2)
    raise AssertionError(f"DB instance {inst_id} was never removed after deletion")

def _wait_cluster_gone(rds, cluster_id, timeout_s=1200) -> None:
    """Poll until a DB cluster's independent read reports not-found."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _not_found(lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id), "DBClusterNotFoundFault"):
            return
        time.sleep(2)
    raise AssertionError(f"DB cluster {cluster_id} was never removed after deletion")

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBCluster with an instance member is rejected with InvalidDBClusterStateFault and leaves the
    cluster and member in place; once the member is removed, the same delete succeeds."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="sim2real",
        MasterUserPassword="Sim2Real#Pass99",
        DBSubnetGroupName=subnet_group,
    )
    state = {"instance_deleted": False, "cluster_deleted": False}

    def _cleanup_cluster():
        if not state["cluster_deleted"]:
            rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)

    # Member is deleted first (LIFO), then the cluster.
    ctx.on_cleanup(_cleanup_cluster)
    _wait_cluster_available(rds, cluster_id)

    inst_id = ctx.unique_name("sim2real-behav-inst-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass="db.t3.medium",
        Engine="aurora-mysql",
        DBClusterIdentifier=cluster_id,
    )

    def _cleanup_instance():
        if not state["instance_deleted"]:
            rds.delete_db_instance(
                DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
            )

    ctx.on_cleanup(_cleanup_instance)
    _wait_available(rds, inst_id)

    code, message = _error_code(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    assert code == ERR_INVALID_DB_CLUSTER_STATE, f"unexpected error code: {code!r}"
    assert message == (
        "Cluster can't be deleted. It still contains DB instances in a non-deleting state."
    ), f"unexpected message: {message!r}"

    # Effect absent: an independent read shows the cluster is untouched and
    # still carries the member that caused the rejection.
    still_there = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert still_there["Status"] == "available", (
        f"cluster {cluster_id} status changed after rejected delete: {still_there['Status']!r}"
    )
    member_ids = {m["DBInstanceIdentifier"] for m in still_there["DBClusterMembers"]}
    assert inst_id in member_ids, f"member {inst_id} missing after rejected delete: {member_ids!r}"

    # Restore: remove the member, then the identical delete call succeeds.
    rds.delete_db_instance(
        DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
    )
    state["instance_deleted"] = True
    _wait_instance_gone(rds, inst_id)

    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    state["cluster_deleted"] = True
    _wait_cluster_gone(rds, cluster_id)


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
