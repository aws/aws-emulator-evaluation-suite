"""delete-cluster-final-snapshot-rejected-while-instance-present."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-final-snapshot-rejected-while-instance-present"
GROUP = "lifecycle"
SERVICES = ["neptune"]


def _client_error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(read, satisfied, timeout_s, interval_s=5):
    """Poll ``read()`` until ``satisfied(value)``; raise with the last value on timeout."""
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = read()
        if satisfied(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not reached within {timeout_s}s, last value was {value!r}")


def _delete_until_gone(name, delete_fn, describe_fn, gone_code, retryable_codes=(),
                        retry_budget_s=180, timeout_s=600, interval_s=5):
    """Call ``delete_fn()``, retrying while it raises a code in ``retryable_codes``, then poll
    ``describe_fn()`` until it raises ``gone_code``. Any other code, or a timeout, raises.
    """
    retry_deadline = time.monotonic() + retry_budget_s
    while True:
        try:
            delete_fn()
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == gone_code:
                return
            if code in retryable_codes and time.monotonic() < retry_deadline:
                time.sleep(interval_s)
                continue
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == gone_code:
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"{name} still present {timeout_s}s after its delete was accepted")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBCluster with a final snapshot is refused while a member instance remains, the
    snapshot is never created, and the same cluster id is unreachable once a plain delete
    succeeds after the instance is gone.
    """
    neptune = ctx.client("neptune")
    network = ctx.network()

    subnet_group = ctx.unique_name("sim2real-neptune-fsr-subnets-")
    neptune.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription=subnet_group,
        SubnetIds=network.subnet_ids,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_until_gone(
        f"subnet group {subnet_group!r}",
        lambda: neptune.delete_db_subnet_group(DBSubnetGroupName=subnet_group),
        lambda: neptune.describe_db_subnet_groups(DBSubnetGroupName=subnet_group),
        "DBSubnetGroupNotFoundFault",
        retryable_codes=("InvalidDBSubnetGroupStateFault",),
    ))

    cluster_id = ctx.unique_name("sim2real-neptune-fsr-cluster-")
    neptune.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="neptune",
        DeletionProtection=False,
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_until_gone(
        f"cluster {cluster_id!r}",
        lambda: neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True),
        lambda: neptune.describe_db_clusters(DBClusterIdentifier=cluster_id),
        "DBClusterNotFoundFault",
        retryable_codes=("InvalidDBClusterStateFault",),
        retry_budget_s=300,
        timeout_s=900,
    ))
    cluster = _poll_until(
        lambda: neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0],
        lambda c: c["Status"] == "available",
        timeout_s=600,
    )
    assert cluster["Status"] == "available", f"cluster never reached available: {cluster!r}"

    instance_id = ctx.unique_name("sim2real-neptune-fsr-instance-")
    neptune.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        DBInstanceClass="db.r5.large",
        Engine="neptune",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_until_gone(
        f"instance {instance_id!r}",
        lambda: neptune.delete_db_instance(DBInstanceIdentifier=instance_id),
        lambda: neptune.describe_db_instances(DBInstanceIdentifier=instance_id),
        "DBInstanceNotFound",
        timeout_s=900,
    ))
    instance = _poll_until(
        lambda: neptune.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=900,
    )
    assert instance["DBClusterIdentifier"] == cluster_id, (
        f"instance should belong to {cluster_id!r}, got {instance['DBClusterIdentifier']!r}"
    )

    # The refusal: a final-snapshot delete while the instance is still a cluster member.
    requested_snapshot = ctx.unique_name("sim2real-neptune-fsr-snapshot-")
    code, message = _client_error(
        lambda: neptune.delete_db_cluster(
            DBClusterIdentifier=cluster_id,
            SkipFinalSnapshot=False,
            FinalDBSnapshotIdentifier=requested_snapshot,
        )
    )
    assert code == "InvalidDBClusterStateFault", (
        f"deleting a cluster with a live member instance should raise "
        f"InvalidDBClusterStateFault, got {code!r}: {message!r}"
    )
    expected_refusal_message = (
        "Cluster can't be deleted. It still contains DB instances in a non-deleting state."
    )
    assert message == expected_refusal_message, (
        f"unexpected refusal message {message!r}, expected {expected_refusal_message!r}"
    )

    # No snapshot exists under the requested identifier after the refusal.
    snap_code, snap_message = _client_error(
        lambda: neptune.describe_db_cluster_snapshots(
            DBClusterSnapshotIdentifier=requested_snapshot
        )
    )
    assert snap_code == "DBClusterSnapshotNotFoundFault", (
        f"the final snapshot {requested_snapshot!r} should not exist after the refused delete, "
        f"direct lookup gave {snap_code!r}: {snap_message!r}"
    )
    expected_snapshot_message = f"DBClusterSnapshot not found: {requested_snapshot}"
    assert snap_message == expected_snapshot_message, (
        f"unexpected snapshot lookup message {snap_message!r}, "
        f"expected {expected_snapshot_message!r}"
    )

    unchanged = neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert unchanged["Status"] == "available", (
        f"cluster {cluster_id!r} should remain available after the refused delete, "
        f"got status {unchanged['Status']!r}"
    )

    # With the member instance gone, a delete that skips the final snapshot succeeds.
    neptune.delete_db_instance(DBInstanceIdentifier=instance_id)
    _poll_until(
        lambda: _describe_instance_or_none(neptune, instance_id),
        lambda v: v is None,
        timeout_s=900,
    )

    neptune.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    _poll_until(
        lambda: _cluster_is_gone(neptune, cluster_id),
        lambda gone: gone,
        timeout_s=600,
    )
    gone_code, gone_message = _client_error(
        lambda: neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)
    )
    assert gone_code == "DBClusterNotFoundFault", (
        f"the cluster should be unreachable once its member instance is gone, "
        f"got {gone_code!r}: {gone_message!r}"
    )
    expected_gone_message = f"DBCluster {cluster_id} not found."
    assert gone_message == expected_gone_message, (
        f"unexpected final lookup message {gone_message!r}, expected {expected_gone_message!r}"
    )


def _describe_instance_or_none(neptune, instance_id):
    """``None`` once ``instance_id`` is gone, else its describe record."""
    try:
        return neptune.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBInstanceNotFound":
            return None
        raise


def _cluster_is_gone(neptune, cluster_id) -> bool:
    """Whether a describe of ``cluster_id`` now raises ``DBClusterNotFoundFault``."""
    try:
        neptune.describe_db_clusters(DBClusterIdentifier=cluster_id)
        return False
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBClusterNotFoundFault":
            return True
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
