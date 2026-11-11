"""snapshot-scoped-ops-not-found-semantics."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}

CHECK = "snapshot-scoped-ops-not-found-semantics"
GROUP = 'error-semantics'
SERVICES = ['redshift']

OTHER_ACCOUNT = "111122223333"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Snapshot-scoped operations agree on the not-found code for an unknown snapshot, and
    restore paths surface the missing *cluster* vs missing *snapshot* distinction correctly."""
    rs = ctx.client("redshift")
    missing_snapshot = ctx.unique_name("sim2real-behav-rs-nosnap-")
    missing_cluster = ctx.unique_name("sim2real-behav-rs-nocluster-")
    cases = {
        "DescribeClusterSnapshots": lambda: rs.describe_cluster_snapshots(
            SnapshotIdentifier=missing_snapshot
        ),
        "DeleteClusterSnapshot": lambda: rs.delete_cluster_snapshot(
            SnapshotIdentifier=missing_snapshot
        ),
        "ModifyClusterSnapshot": lambda: rs.modify_cluster_snapshot(
            SnapshotIdentifier=missing_snapshot, ManualSnapshotRetentionPeriod=3
        ),
        "CopyClusterSnapshot": lambda: rs.copy_cluster_snapshot(
            SourceSnapshotIdentifier=missing_snapshot,
            TargetSnapshotIdentifier=ctx.unique_name("sim2real-behav-rs-copytgt-"),
        ),
        "AuthorizeSnapshotAccess": lambda: rs.authorize_snapshot_access(
            SnapshotIdentifier=missing_snapshot, AccountWithRestoreAccess=OTHER_ACCOUNT
        ),
        "RevokeSnapshotAccess": lambda: rs.revoke_snapshot_access(
            SnapshotIdentifier=missing_snapshot, AccountWithRestoreAccess=OTHER_ACCOUNT
        ),
        "RestoreFromClusterSnapshot": lambda: rs.restore_from_cluster_snapshot(
            ClusterIdentifier=ctx.unique_name("sim2real-behav-rs-restore-"), SnapshotIdentifier=missing_snapshot
        ),
        "DescribeNodeConfigurationOptions": lambda: rs.describe_node_configuration_options(
            ActionType="restore-cluster", SnapshotIdentifier=missing_snapshot
        ),
        "RestoreTableFromClusterSnapshot": lambda: rs.restore_table_from_cluster_snapshot(
            ClusterIdentifier=missing_cluster,
            SnapshotIdentifier=missing_snapshot,
            SourceDatabaseName="devdb",
            SourceTableName="sim2real_behav_src",
            NewTableName="sim2real_behav_dst",
        ),
    }
    observed = _probe_codes(cases)
    expected = dict.fromkeys(cases, "ClusterSnapshotNotFound")
    # RestoreTable resolves the target cluster first, so the missing cluster wins.
    expected["RestoreTableFromClusterSnapshot"] = "ClusterNotFound"
    assert observed == expected, f"snapshot not-found contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
