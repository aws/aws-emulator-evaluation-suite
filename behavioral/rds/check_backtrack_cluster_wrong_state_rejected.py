"""backtrack-cluster-wrong-state-rejected."""
from __future__ import annotations

import datetime as dt
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backtrack-cluster-wrong-state-rejected"
GROUP = "error-semantics"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BacktrackDBCluster on an Aurora MySQL cluster created without backtrack is rejected with
    InvalidDBClusterStateFault and its exact message, leaves no backtrack record, and the
    cluster still accepts an unrelated modification (it is not broadly stuck)."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-backtrack-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DeletionProtection=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
        # BacktrackWindow omitted (default 0, disabled); backtrack can only be enabled at
        # create/restore time, never via ModifyDBCluster.
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    cluster = _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)
    assert cluster.get("BacktrackWindow", 0) == 0, (
        f"expected BacktrackWindow 0 (disabled) on a freshly created cluster, got "
        f"{cluster.get('BacktrackWindow')!r}"
    )

    backtrack_to = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
    code, message = _error_detail(
        lambda: rds.backtrack_db_cluster(
            DBClusterIdentifier=cluster_id, BacktrackTo=backtrack_to, Force=True
        )
    )
    assert code == "InvalidDBClusterStateFault", f"unexpected error code {code!r}: {message!r}"
    expected = "Backtrack is not currently available to this cluster."
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Effect absent: no backtrack record was created.
    backtracks = rds.describe_db_cluster_backtracks(DBClusterIdentifier=cluster_id)[
        "DBClusterBacktracks"
    ]
    assert backtracks == [], f"expected no backtrack records, got {backtracks!r}"

    # Control: an unrelated modification succeeds (ModifyDBCluster cannot enable backtrack).
    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id, BackupRetentionPeriod=3, ApplyImmediately=True
    )
    _wait_backup_retention(ctx, cluster_id, 3, timeout_s=180)


def _error_detail(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(
        f"real AWS rejects BacktrackDBCluster on a backtrack-disabled cluster, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


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


def _wait_backup_retention(ctx, cluster_id, target_value, timeout_s=180, poll_s=10) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last.get("BackupRetentionPeriod") == target_value:
            return
        time.sleep(poll_s)
    raise AssertionError(
        f"cluster {cluster_id} BackupRetentionPeriod never reached {target_value}, last observed "
        f"{last and last.get('BackupRetentionPeriod')!r}"
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
