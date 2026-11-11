"""cluster-deletion-protection-delete-rejected."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-deletion-protection-delete-rejected"
GROUP = "server-side"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBCluster is blocked server-side whenever DeletionProtection=true, on every retry,
    and only succeeds after an explicit ModifyDBCluster disables it -- deletion protection is
    not a client-side hint the emulator can silently ignore."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-delprot-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DeletionProtection=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    cleanup_state = {"deleted": False}

    def _cleanup():
        if cleanup_state["deleted"]:
            return
        rds.modify_db_cluster(
            DBClusterIdentifier=cluster_id, DeletionProtection=False, ApplyImmediately=True
        )
        _wait_deletion_protection(ctx, cluster_id, False, timeout_s=180)
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)

    ctx.on_cleanup(_cleanup)
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    # Break exactly one thing: try to delete while protection is still on -- twice, to show it
    # isn't a one-shot fluke the caller could just retry past.
    for attempt in range(2):
        code, message = _error_detail(
            lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        )
        assert code == "InvalidParameterCombination", (
            f"attempt {attempt}: unexpected error code {code!r}: {message!r}"
        )
        expected = "Cannot delete protected Cluster, please disable deletion protection and try again."
        assert message == expected, (
            f"attempt {attempt}: unexpected message {message!r} (expected {expected!r})"
        )

    # Effect absent: the cluster still exists and is untouched.
    still_there = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert still_there["DBClusterIdentifier"] == cluster_id, (
        f"expected cluster {cluster_id!r} to still exist after the rejected delete, "
        f"describe returned {still_there['DBClusterIdentifier']!r}"
    )
    assert still_there["DeletionProtection"] is True, (
        f"cluster {cluster_id!r} DeletionProtection should remain True after the rejected "
        f"delete, got {still_there['DeletionProtection']!r}"
    )

    # Positive control (same file): disabling protection explicitly, then deleting, succeeds.
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id, DeletionProtection=False, ApplyImmediately=True
    )
    _wait_deletion_protection(ctx, cluster_id, False, timeout_s=180)
    rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    cleanup_state["deleted"] = True
    _wait_cluster_gone(ctx, cluster_id, timeout_s=900)


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _error_detail(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError("DeleteDBCluster on a deletion-protected cluster succeeded; expected a rejection")


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_deletion_protection(ctx, cluster_id, target_value, timeout_s=180, poll_s=10) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last.get("DeletionProtection") == target_value:
            return
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} DeletionProtection never reached {target_value}, "
        f"last observed {last and last.get('DeletionProtection')!r}"
    )


def _wait_cluster_gone(ctx, cluster_id, timeout_s=900, poll_s=20) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except rds.exceptions.DBClusterNotFoundFault:
            return
        time.sleep(poll_s)
    raise AssertionError(f"cluster {cluster_id} was never removed after deletion")


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
