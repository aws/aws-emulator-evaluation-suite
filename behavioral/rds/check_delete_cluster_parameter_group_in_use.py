"""delete-cluster-parameter-group-in-use."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags
import secrets

CHECK = "delete-cluster-parameter-group-in-use"
GROUP = 'cluster_parameter_groups'
SERVICES = ['rds']

ERR_INVALID_PARAMETER_GROUP_STATE = "InvalidDBParameterGroupState"
ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"


def _error_code(fn):
    """Call fn() and return its error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=600, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _default_param_family(ctx, engine: str) -> str:
    rds = ctx.client("rds")
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]


def _wait_cluster_gone(ctx, cluster_id, *, timeout_s=900, poll_s=20) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(poll_s)
    raise AssertionError(f"cluster {cluster_id} was never removed after deletion")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBClusterParameterGroup on a group attached to a live cluster fails with
    InvalidDBParameterGroupState on every attempt and leaves it attached; after the cluster moves
    to the default group, the same delete succeeds and the group reads as not found."""
    rds = ctx.client("rds")
    subnet_group = _network_db_subnet_group(ctx, rds)
    family = _default_param_family(ctx, "aurora-mysql")
    default_pg_name = f"default.{family}"

    pg_name = ctx.unique_name("sim2real-behav-cpg-inuse-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=pg_name,
        DBParameterGroupFamily=family,
        Description="behavioral check",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    cluster_id = ctx.unique_name("sim2real-behav-clu-")
    cleanup_state = {"pg_deleted": False, "cluster_deleted": False}

    def _cleanup():
        if not cleanup_state["cluster_deleted"]:
            try:
                rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "DBClusterNotFoundFault":
                    raise
            _wait_cluster_gone(ctx, cluster_id)
            cleanup_state["cluster_deleted"] = True
        if not cleanup_state["pg_deleted"]:
            rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=pg_name)
            cleanup_state["pg_deleted"] = True

    ctx.on_cleanup(_cleanup)

    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="admin",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        BackupRetentionPeriod=1,
        DBClusterParameterGroupName=pg_name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"cluster {cluster_id} available",
    )

    # Repeat the delete to show the refusal persists across retries.
    for attempt in range(2):
        code, message = _error_code(
            lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=pg_name)
        )
        assert code == ERR_INVALID_PARAMETER_GROUP_STATE, (
            f"attempt {attempt}: unexpected error code {code!r}"
        )
        assert message == (
            "One or more database instances are still members of this parameter group "
            f"{pg_name}, so the group cannot be deleted"
        ), f"attempt {attempt}: unexpected message {message!r}"

    # Effect absent: the group still exists and is still attached to the cluster.
    still_there = rds.describe_db_cluster_parameter_groups(
        DBClusterParameterGroupName=pg_name
    )["DBClusterParameterGroups"][0]
    assert still_there["DBClusterParameterGroupName"] == pg_name, still_there

    cluster_now = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster_now["DBClusterParameterGroup"] == pg_name, (
        f"cluster drifted off {pg_name!r} onto {cluster_now['DBClusterParameterGroup']!r}"
    )

    # Move the cluster onto the family's default group so the target group is unused.
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id,
        DBClusterParameterGroupName=default_pg_name,
        ApplyImmediately=True,
    )
    _poll_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c.get("DBClusterParameterGroup") == default_pg_name and c.get("Status") == "available",
        timeout_s=300,
        interval_s=10,
        description=f"cluster {cluster_id} moved onto {default_pg_name}",
    )

    # Control: the same delete now succeeds and the group is gone.
    rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=pg_name)
    cleanup_state["pg_deleted"] = True
    gone_code, gone_message = _error_code(
        lambda: rds.describe_db_cluster_parameter_groups(DBClusterParameterGroupName=pg_name)
    )
    assert gone_code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, f"unexpected error code: {gone_code}"
    assert gone_message == f"DBClusterParameterGroup not found: {pg_name}", (
        f"unexpected not-found message: {gone_message!r}"
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
