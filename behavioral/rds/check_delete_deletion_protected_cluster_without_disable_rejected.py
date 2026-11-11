"""delete-deletion-protected-cluster-without-disable-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-deletion-protected-cluster-without-disable-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]

_MASTER_USER = "sim2realadmin"
_MASTER_PASS = "Sim2RealPwd123"

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-delprot"},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """DeleteDBCluster on a deletion-protected cluster fails InvalidParameterCombination twice.

    The cluster stays available; after ModifyDBCluster disables protection the delete removes it.
    """
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-delprot-")

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername=_MASTER_USER,
        MasterUserPassword=_MASTER_PASS,
        DeletionProtection=True,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _force_delete_cluster(rds, cluster_id))
    _wait_for_cluster_status(rds, cluster_id, "available", timeout_s=600)

    cluster = _describe_cluster(rds, cluster_id)
    assert cluster["DeletionProtection"] is True, (
        f"expected DeletionProtection=True right after create, got {cluster['DeletionProtection']!r}"
    )

    # Delete twice: the rejection must hold on a retry of the identical call.
    for attempt in range(2):
        code, message = _error_code(
            lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        )
        assert code == "InvalidParameterCombination", (
            f"attempt {attempt}: expected InvalidParameterCombination for DeleteDBCluster on a "
            f"deletion-protected cluster, got {code!r}"
        )
        assert message == (
            "Cannot delete protected Cluster, please disable deletion protection and try again."
        ), f"attempt {attempt}: unexpected message {message!r}"

    cluster_after = _describe_cluster(rds, cluster_id)
    assert cluster_after["Status"] == "available", (
        f"expected Status='available' after the rejected delete, got {cluster_after['Status']!r}"
    )
    assert cluster_after["DeletionProtection"] is True, (
        f"expected DeletionProtection to remain True after the rejected delete, "
        f"got {cluster_after['DeletionProtection']!r}"
    )

    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id, DeletionProtection=False, ApplyImmediately=True
    )
    _wait_for_deletion_protection(rds, cluster_id, expected=False, timeout_s=300)
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    _wait_for_cluster_gone(rds, cluster_id, timeout_s=600)

    # A mutation on the deleted identifier fails with the same not-found code as the read.
    dead_code, dead_message = _error_code(
        lambda: rds.modify_db_cluster(DBClusterIdentifier=cluster_id, ApplyImmediately=True)
    )
    assert dead_code == "DBClusterNotFoundFault", (
        f"expected ModifyDBCluster on the deleted cluster id to fail with DBClusterNotFoundFault, "
        f"got {dead_code!r}"
    )
    assert dead_message == "DBCluster not found", (
        f"unexpected ModifyDBCluster not-found message on the deleted cluster id: {dead_message!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its botocore error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _describe_cluster(rds: Any, cluster_id: str) -> dict[str, Any]:
    return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]


def _wait_for_cluster_status(rds: Any, cluster_id: str, status: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = _describe_cluster(rds, cluster_id)
        if cluster["Status"] == status:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached status={status!r} in {timeout_s}s")


def _wait_for_deletion_protection(rds: Any, cluster_id: str, *, expected: bool, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = _describe_cluster(rds, cluster_id)
        if cluster["DeletionProtection"] == expected and cluster["Status"] == "available":
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} DeletionProtection never became {expected!r}")


def _wait_for_cluster_gone(rds: Any, cluster_id: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            _describe_cluster(rds, cluster_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} was never removed within {timeout_s}s")


def _force_delete_cluster(rds: Any, cluster_id: str) -> None:
    try:
        rds.modify_db_cluster(
            DBClusterIdentifier=cluster_id, DeletionProtection=False, ApplyImmediately=True
        )
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "DBClusterNotFoundFault",
            "DBClusterParameterGroupNotFound",
            "DBParameterGroupNotFound",
            "DBSubnetGroupNotFoundFault",
            "DomainNotFoundFault",
            "OptionGroupNotFoundFault",
        ):
            raise
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBClusterNotFoundFault":
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
