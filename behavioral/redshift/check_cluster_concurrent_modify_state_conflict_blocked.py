"""cluster-concurrent-modify-state-conflict-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-concurrent-modify-state-conflict-blocked"
GROUP = "concurrency"
SERVICES = ["redshift"]

_POLL_INTERVAL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyClusterDbRevision issued while a ModifyCluster resize is already applying to
    the same cluster is rejected with InvalidClusterState instead of both proceeding,
    and the cluster's revision is left untouched by the rejected call.
    """
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-behav-cl-").lower()

    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        ClusterType="single-node",
        NodeType="ra3.xlplus",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2Real123!",
        DBName="sim2real",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))

    _wait_cluster_status(ctx, cluster_id, {"available"}, timeout_s=_budget_s(ctx, 1200), interval_s=_POLL_INTERVAL_S)

    db_revision = redshift.describe_cluster_db_revisions(ClusterIdentifier=cluster_id)[
        "ClusterDbRevisions"
    ][0]
    revision_targets = db_revision.get("RevisionTargets", [])
    # A freshly created cluster is almost always already on the latest revision for its
    # track, so RevisionTargets is typically empty. That is not a missing prerequisite for
    # *this* check: any syntactically valid RevisionTarget -- an alternate one if offered,
    # else the cluster's own current revision -- is enough to probe whether the busy-state
    # gate (InvalidClusterState) fires before target-specific validation does.
    revision_target = (
        revision_targets[0]["DatabaseRevision"]
        if revision_targets
        else db_revision["CurrentDatabaseRevision"]
    )
    revision_before = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
        "ClusterRevisionNumber"
    ]

    # Kick off a long-running modification (resize 1 -> 2 nodes). Real AWS can still answer
    # InvalidClusterState for a short settling window right after a cluster first reaches
    # "available", so ride out that transient rather than letting it masquerade as a defect.
    modify_resp = _retry_invalid_cluster_state(
        lambda: redshift.modify_cluster(
            ClusterIdentifier=cluster_id,
            ClusterType="multi-node",
            NodeType="ra3.xlplus",
            NumberOfNodes=2,
        ),
        timeout_s=_budget_s(ctx, 600.0),
        ctx=ctx,
    )
    busy_status = modify_resp["Cluster"]["ClusterStatus"]
    assert busy_status != "available", f"expected a non-available status, got {busy_status!r}"

    code, message = _error(
        lambda: redshift.modify_cluster_db_revision(
            ClusterIdentifier=cluster_id, RevisionTarget=revision_target
        )
    )
    assert code == "InvalidClusterState", f"expected InvalidClusterState, got {code!r}"
    expected = (
        "Cannot modify the cluster-db-revision right now because another operation is running. "
        "Check the cluster's status and retry when the cluster is available."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: the racing call must not have changed the cluster's revision.
    revision_during = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
        "ClusterRevisionNumber"
    ]
    assert revision_during == revision_before, (
        f"ClusterRevisionNumber changed despite rejected call: "
        f"{revision_before!r} -> {revision_during!r}"
    )

    # Wait for the resize to finish so we can run a positive control.
    _wait_cluster_status(ctx, cluster_id, {"available"}, timeout_s=_budget_s(ctx, 1800), interval_s=_POLL_INTERVAL_S)

    # Positive control: once the cluster is no longer busy, a mutating call succeeds. Same
    # settling-window caveat as above applies right after this second "available" transition.
    _retry_invalid_cluster_state(
        lambda: redshift.modify_cluster(ClusterIdentifier=cluster_id, ManualSnapshotRetentionPeriod=3),
        timeout_s=_budget_s(ctx, 600.0),
        ctx=ctx,
    )
    _poll_until(
        lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ManualSnapshotRetentionPeriod"
        ],
        lambda v: v == 3,
        timeout_s=_budget_s(ctx, 120),
        interval_s=_POLL_INTERVAL_S,
        ctx=ctx,
    )


def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_invalid_cluster_state(fn, *, timeout_s: float = 180.0, interval_s: float = _POLL_INTERVAL_S, ctx=None):
    """A cluster that has only just reached "available" can still answer
    InvalidClusterState for a short settling window even though describe_clusters already
    reports it as available -- that is not the fault under test, so retry through it on a
    bounded deadline rather than letting it masquerade as a rejection.
    """
    deadline = time.monotonic() + timeout_s
    last_transient = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidClusterState":
                raise
            last_transient = exc.response["Error"]["Code"]
            time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("cluster accepting the modification: the run budget ended first; not graded")
    raise AssertionError(f"still {last_transient!r} after {timeout_s}s settling window")


def _wait_cluster_status(ctx, cluster_id: str, target_statuses: set[str], *, timeout_s: float, interval_s: float) -> str:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
            "ClusterStatus"
        ]
        if status in target_statuses:
            return status
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"cluster never reached {target_statuses}, last status={status!r}")


def _delete_cluster(redshift, cluster_id: str) -> None:
    """Delete the cluster, waiting out an in-flight resize (DeleteCluster answers
    InvalidClusterState until the cluster is no longer busy)."""
    deadline = time.monotonic() + 1740
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() > deadline:
                raise
            time.sleep(_POLL_INTERVAL_S)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, ctx=None):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if predicate(value):
        return value
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
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
