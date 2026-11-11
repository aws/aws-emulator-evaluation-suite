"""failover-primary-compute-transition."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "failover-primary-compute-transition"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FailoverPrimaryCompute on a Multi-AZ cluster promotes the secondary compute, and the new secondary
    is in a different Availability Zone from the new primary (AWS picks which).

    Reference: https://docs.aws.amazon.com/redshift/latest/mgmt/test-cluster-multi-az.html
    """
    redshift = ctx.client("redshift")
    cluster_id = _create_multi_az_cluster(ctx)

    before = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    multi_az_before = before.get("MultiAZ")
    assert multi_az_before == "Enabled" or multi_az_before is True, (
        f"expected the cluster to report Multi-AZ enabled before failover, got MultiAZ={multi_az_before!r}"
    )
    primary_az_before = before["AvailabilityZone"]
    secondary_az_before = before["MultiAZSecondary"]["AvailabilityZone"]
    assert primary_az_before != secondary_az_before, (
        f"expected distinct primary/secondary AZs before failover, both were {primary_az_before!r}"
    )

    _call_failover_with_retry(redshift, cluster_id, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)

    after = _poll_until_az_swapped(
        ctx, redshift, cluster_id, primary_az_before, timeout_s=_budget_s(ctx, 1200.0)
    )
    assert after["AvailabilityZone"] == secondary_az_before, (
        f"expected the primary AZ to become the pre-failover secondary AZ "
        f"{secondary_az_before!r}, got {after['AvailabilityZone']!r}"
    )
    assert after["MultiAZSecondary"]["AvailabilityZone"] != after["AvailabilityZone"], (
        f"expected the new secondary in an Availability Zone other than the new primary's "
        f"{after['AvailabilityZone']!r}, got {after['MultiAZSecondary']!r}"
    )
    assert after["ClusterStatus"] == "available", (
        f"expected the cluster to settle in 'available' after failover, got {after['ClusterStatus']!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _waiter_config(ctx, cap_s, delay_s=2):
    """A WaiterConfig polling every delay_s seconds for at most _budget_s(ctx, cap_s) seconds."""
    return {"Delay": delay_s, "MaxAttempts": max(1, int(_budget_s(ctx, cap_s) // delay_s))}


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _rand_password() -> str:
    return f"S2r{secrets.token_hex(4)}Aa1Xy"


def _shared_network_subnets(ctx) -> list[str]:
    """One subnet per Availability Zone of the run's shared network (ctx.network())."""
    subnet_ids = ctx.network().subnet_ids
    if len(subnet_ids) < 2:
        raise AssertionError(
            f"the shared network spans {len(subnet_ids)} Availability Zone(s); a Multi-AZ "
            "Redshift deployment needs at least 2"
        )
    return subnet_ids


def _create_multi_az_cluster(ctx) -> str:
    redshift = ctx.client("redshift")
    subnet_ids = _shared_network_subnets(ctx)
    subnet_group_name = ctx.unique_name("sim2real-subg-")
    redshift.create_cluster_subnet_group(
        ClusterSubnetGroupName=subnet_group_name,
        Description="sim2real behavioral fidelity check",
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(redshift, subnet_group_name))

    cluster_id = ctx.unique_name("sim2real-mazclu-")
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType="ra3.xlplus",
        ClusterType="multi-node",
        NumberOfNodes=2,
        MultiAZ=True,
        MasterUsername="s2radmin",
        MasterUserPassword=_rand_password(),
        ClusterSubnetGroupName=subnet_group_name,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_cluster(redshift, cluster_id))

    waiter = redshift.get_waiter("cluster_available")
    try:
        waiter.wait(
            ClusterIdentifier=cluster_id,
            WaiterConfig=_waiter_config(ctx, 3600),
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(f"cluster {cluster_id} available: the run budget ended first; not graded") from exc
        raise AssertionError(f"cluster {cluster_id} never became available: {exc}")

    # FailoverPrimaryCompute rejects a cluster with InvalidClusterState ("You can't
    # failover primary compute of your cluster which doesn't have backup") until it
    # has completed at least one backup; a manual snapshot satisfies that without
    # waiting on the automated backup schedule.
    _create_first_backup(ctx, redshift, cluster_id)
    return cluster_id


def _create_first_backup(ctx, redshift, cluster_id: str) -> None:
    snapshot_id = ctx.unique_name("sim2real-mazclu-snap-")
    redshift.create_cluster_snapshot(
        ClusterIdentifier=cluster_id,
        SnapshotIdentifier=snapshot_id,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _safe_delete_snapshot(redshift, cluster_id, snapshot_id)
    )
    waiter = redshift.get_waiter("snapshot_available")
    try:
        waiter.wait(
            SnapshotIdentifier=snapshot_id,
            WaiterConfig=_waiter_config(ctx, 3600),
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(f"snapshot {snapshot_id} available: the run budget ended first; not graded") from exc
        raise AssertionError(
            f"first backup snapshot {snapshot_id} for cluster {cluster_id} never "
            f"became available: {exc}"
        )


def _safe_delete_snapshot(redshift, cluster_id: str, snapshot_id: str) -> None:
    try:
        redshift.delete_cluster_snapshot(
            SnapshotIdentifier=snapshot_id, SnapshotClusterIdentifier=cluster_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ClusterSnapshotNotFoundFault":
            return
        raise


def _call_failover_with_retry(redshift, cluster_id: str, timeout_s: float, ctx=None) -> None:
    """FailoverPrimaryCompute can reject a just-backed-up, otherwise-available
    Multi-AZ cluster with InvalidClusterState ("...now. Try again later.") while
    internal post-snapshot bookkeeping settles; any other InvalidClusterState (e.g. "no
    backup yet") is a real precondition failure and is not retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            redshift.failover_primary_compute(ClusterIdentifier=cluster_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidClusterState" and "try again later" in message.lower():
                if time.monotonic() >= deadline:
                    if ctx is not None and _budget_spent(ctx):
                        raise TimeoutError(
                            f"FailoverPrimaryCompute on {cluster_id} accepted: the run budget ended first; not graded"
                        ) from exc
                    raise AssertionError(
                        f"cluster {cluster_id} still refused FailoverPrimaryCompute "
                        f"with a transient InvalidClusterState after {timeout_s}s: {message}"
                    )
                time.sleep(2)
                continue
            raise


def _poll_until_az_swapped(ctx, redshift, cluster_id, original_primary_az, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if (
            last["ClusterStatus"] == "available"
            and last["AvailabilityZone"] != original_primary_az
            and last.get("MultiAZSecondary", {}).get("AvailabilityZone")
        ):
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} failover settled: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never completed the primary-compute failover "
        f"within {timeout_s}s; last observed state: {last}"
    )


def _delete_cluster(redshift, cluster_id: str) -> None:
    """Delete the cluster and wait until it is gone; raise if it is not. After a failover the
    cluster keeps provisioning its new secondary for a while, and DeleteCluster answers
    InvalidClusterState ("There is an operation running on the Cluster") until that finishes, so
    the delete is retried while that holds."""
    deadline = time.monotonic() + 900.0
    while True:
        try:
            redshift.delete_cluster(
                ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundFault":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    waiter = redshift.get_waiter("cluster_deleted")
    try:
        waiter.wait(
            ClusterIdentifier=cluster_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": 420},
        )
    except WaiterError as exc:
        raise RuntimeError(f"cluster {cluster_id} was not deleted: {exc}") from exc


def _safe_delete_subnet_group(redshift, name: str) -> None:
    for _ in range(150):
        try:
            redshift.delete_cluster_subnet_group(ClusterSubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterSubnetGroupNotFoundFault":
                return
            if code == "InvalidClusterSubnetGroupStateFault":
                time.sleep(2)
                continue
            raise
    raise RuntimeError(f"cluster subnet group {name} is still in use and was not deleted")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
