"""cluster-scoped-ops-not-found-semantics."""

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

CHECK = "cluster-scoped-ops-not-found-semantics"
GROUP = 'error-semantics'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every cluster-scoped operation reports the SAME not-found code for an unknown cluster.

    Emulators commonly special-case one or two of these and fall through to a
    generic 400/500 for the rest, so the whole family is asserted at once.
    """
    rs = ctx.client("redshift")
    missing = ctx.unique_name("sim2real-behav-rs-missing-")
    cases = {
        "DescribeClusters": lambda: rs.describe_clusters(ClusterIdentifier=missing),
        "DeleteCluster": lambda: rs.delete_cluster(ClusterIdentifier=missing, SkipFinalClusterSnapshot=True),
        "ModifyCluster": lambda: rs.modify_cluster(ClusterIdentifier=missing, AllowVersionUpgrade=True),
        "RebootCluster": lambda: rs.reboot_cluster(ClusterIdentifier=missing),
        "PauseCluster": lambda: rs.pause_cluster(ClusterIdentifier=missing),
        "ResumeCluster": lambda: rs.resume_cluster(ClusterIdentifier=missing),
        "ResizeCluster": lambda: rs.resize_cluster(ClusterIdentifier=missing, NumberOfNodes=2),
        "CancelResize": lambda: rs.cancel_resize(ClusterIdentifier=missing),
        "DescribeResize": lambda: rs.describe_resize(ClusterIdentifier=missing),
        "RotateEncryptionKey": lambda: rs.rotate_encryption_key(ClusterIdentifier=missing),
        "ModifyClusterMaintenance": lambda: rs.modify_cluster_maintenance(ClusterIdentifier=missing),
        "ModifyClusterIamRoles": lambda: rs.modify_cluster_iam_roles(ClusterIdentifier=missing),
        "ModifyClusterSnapshotSchedule": lambda: rs.modify_cluster_snapshot_schedule(
            ClusterIdentifier=missing, DisassociateSchedule=True
        ),
        "DescribeClusterDbRevisions": lambda: rs.describe_cluster_db_revisions(ClusterIdentifier=missing),
        "DescribeLoggingStatus": lambda: rs.describe_logging_status(ClusterIdentifier=missing),
        "DisableLogging": lambda: rs.disable_logging(ClusterIdentifier=missing),
        "GetClusterCredentials": lambda: rs.get_cluster_credentials(
            DbUser="tempuser", ClusterIdentifier=missing
        ),
        "GetClusterCredentialsWithIAM": lambda: rs.get_cluster_credentials_with_iam(
            ClusterIdentifier=missing
        ),
        "DescribeTableRestoreStatus": lambda: rs.describe_table_restore_status(ClusterIdentifier=missing),
        "CreateUsageLimit": lambda: rs.create_usage_limit(
            ClusterIdentifier=missing, FeatureType="spectrum", LimitType="data-scanned", Amount=1
        ),
    }
    observed = _probe_codes(cases)
    expected = dict.fromkeys(cases, "ClusterNotFound")
    assert observed == expected, f"cluster not-found contract drift:\n expected={expected}\n observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
