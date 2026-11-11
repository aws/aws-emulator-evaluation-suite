"""create-shard-group-on-non-limitless-cluster-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-shard-group-on-non-limitless-cluster-rejected"
GROUP = "error-semantics"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBShardGroup on a non-Limitless Aurora PostgreSQL cluster fails with
    InvalidParameterCombination naming the engine version, creates no shard group, and a
    manual cluster snapshot still succeeds afterwards."""
    cluster_id = ctx.unique_name("sim2real-clus-")
    shard_id = ctx.unique_name("sim2real-shard-")
    rds = ctx.client("rds")

    # A plain provisioned Aurora cluster, never enabled for Aurora Limitless Database.
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real!Pwd01",
        DatabaseName="simdb",
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_id))
    _wait_for_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    detail = _error_detail(
        lambda: rds.create_db_shard_group(
            DBShardGroupIdentifier=shard_id, DBClusterIdentifier=cluster_id, MaxACU=128.0
        )
    )
    assert detail["code"] == "InvalidParameterCombination", detail
    # The bare code is also returned for unrelated malformed-request rejections, so pin the
    # exact message: it names the Limitless incompatibility and the cluster's engine version.
    engine_version = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0][
        "EngineVersion"
    ]
    expected = (
        "The request includes Aurora Limitless Database attributes, which aren't available for "
        "the engine version of your DB cluster (Aurora PostgreSQL (Compatible with PostgreSQL "
        f"{engine_version})). Upgrade to an engine version that's compatible with Aurora "
        "Limitless Database."
    )
    assert detail["message"] == expected, f"expected message {expected!r}, got {detail['message']!r}"

    # Effect absent: no shard group was created.
    not_found = _error_detail(
        lambda: rds.describe_db_shard_groups(DBShardGroupIdentifier=shard_id)
    )
    assert not_found["code"] == "DBShardGroupNotFound", not_found
    expected_nf = f"DBShardGroup {shard_id} not found."
    assert not_found["message"] == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found['message']!r}"
    )

    # Control: a manual snapshot succeeds. The cluster can briefly reject a snapshot right after
    # reaching "available", so the create is retried.
    snap_id = ctx.unique_name("sim2real-snap-")
    _retry_snapshot_create(ctx, cluster_id, snap_id, timeout_s=300)
    ctx.on_cleanup(lambda: _safe_delete_cluster_snapshot(ctx, snap_id))
    _wait_for_cluster_snapshot_status(ctx, snap_id, "available", timeout_s=600)


def _retry_snapshot_create(ctx, cluster_id: str, snap_id: str, *, timeout_s: float) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            rds.create_db_cluster_snapshot(
                DBClusterSnapshotIdentifier=snap_id,
                DBClusterIdentifier=cluster_id,
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidDBClusterSnapshotStateFault":
                raise
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"cluster snapshot creation never became possible: {last_exc}")


def _error_detail(fn: Callable[[], Any]) -> dict[str, str]:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"code": err.get("Code"), "message": err.get("Message", "")}
    raise AssertionError("expected a ClientError, call succeeded")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float = 15.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _wait_for_cluster_status(ctx, cluster_id: str, status: str, *, timeout_s: float) -> None:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]["Status"]

    _poll_until(probe, lambda s: s == status, timeout_s=timeout_s)


def _wait_for_cluster_snapshot_status(ctx, snap_id: str, status: str, *, timeout_s: float) -> None:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id)[
            "DBClusterSnapshots"
        ][0]["Status"]

    _poll_until(probe, lambda s: s == status, timeout_s=timeout_s)


def _safe_delete_cluster(ctx, cluster_id: str) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBClusterNotFoundFault", "InvalidDBClusterStateFault"):
            raise


def _safe_delete_cluster_snapshot(ctx, snap_id: str) -> None:
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    try:
        rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterSnapshotNotFoundFault":
            raise


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
