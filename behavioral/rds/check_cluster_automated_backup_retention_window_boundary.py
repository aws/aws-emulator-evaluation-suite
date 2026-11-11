"""cluster-automated-backup-retention-window-boundary."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-automated-backup-retention-window-boundary"
GROUP = "visibility-timeout-ttl"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Lowering a cluster's BackupRetentionPeriod updates its DescribeDBClusterAutomatedBackups
    entry: both the reported BackupRetentionPeriod and the RestoreWindow span shrink to match."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-backupwin-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DeletionProtection=False,
        BackupRetentionPeriod=7,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    entry_before = _wait_automated_backup_retention(ctx, cluster_id, 7, timeout_s=300)
    assert entry_before["BackupRetentionPeriod"] == 7, (
        f"expected automated backup entry retention 7, got {entry_before.get('BackupRetentionPeriod')!r}"
    )
    _assert_window_bounded_by_retention(entry_before["RestoreWindow"], retention_days=7)

    rds.modify_db_cluster(
        DBClusterIdentifier=cluster_id, BackupRetentionPeriod=1, ApplyImmediately=True
    )
    _wait_cluster_retention(ctx, cluster_id, 1, timeout_s=300)

    entry_after = _wait_automated_backup_retention(ctx, cluster_id, 1, timeout_s=300)
    assert entry_after["BackupRetentionPeriod"] == 1, (
        f"automated backup entry retention did not shrink to 1, still {entry_after!r}"
    )
    # The RestoreWindow must be derived from the new retention, not still span the old one.
    _assert_window_bounded_by_retention(entry_after["RestoreWindow"], retention_days=1)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_cluster_retention(ctx, cluster_id, target_value, timeout_s=300, poll_s=2) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last.get("BackupRetentionPeriod") == target_value:
            return
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"cluster {cluster_id} BackupRetentionPeriod {target_value}: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"cluster {cluster_id} BackupRetentionPeriod never reached {target_value}, "
        f"last observed {last and last.get('BackupRetentionPeriod')!r}"
    )


def _assert_window_bounded_by_retention(window, retention_days, clock_skew_slack_s=3600) -> None:
    earliest, latest = window["EarliestTime"], window["LatestTime"]
    assert earliest <= latest, f"restore window is inverted: {window!r}"
    span_s = (latest - earliest).total_seconds()
    max_span_s = retention_days * 86400 + clock_skew_slack_s
    assert span_s <= max_span_s, (
        f"restore window spans {span_s:.0f}s, exceeding the {retention_days}-day retention "
        f"({max_span_s:.0f}s incl. slack): {window!r}"
    )


def _wait_automated_backup_retention(ctx, cluster_id, target_value, timeout_s=300, poll_s=2):
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        entries = rds.describe_db_cluster_automated_backups(DBClusterIdentifier=cluster_id)[
            "DBClusterAutomatedBackups"
        ]
        active = [e for e in entries if e.get("BackupRetentionPeriod") == target_value]
        if active:
            return active[0]
        last = entries[0] if entries else None
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"cluster {cluster_id} automated backup retention {target_value}: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"cluster {cluster_id} automated backup entry never reported retention "
        f"{target_value}, last observed {last!r}"
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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
