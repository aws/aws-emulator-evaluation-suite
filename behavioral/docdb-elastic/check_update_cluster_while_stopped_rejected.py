"""update-cluster-while-stopped-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-cluster-while-stopped-rejected"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCluster on a STOPPED cluster is rejected with ConflictException and the
    shard configuration is left unchanged; the same cluster, once restarted back to
    ACTIVE, accepts the identical update (positive control, reusing the same resource)."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-updstop-")

    cluster_arn = client.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        shardInstanceCount=1,
        tags={"sim2real-check": CHECK},
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(client, cluster_arn))
    _wait_for_status(client, cluster_arn, {"ACTIVE"})

    client.stop_cluster(clusterArn=cluster_arn)
    _wait_for_status(client, cluster_arn, {"STOPPED"})

    try:
        client.update_cluster(clusterArn=cluster_arn, shardInstanceCount=2)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
    else:
        raise AssertionError("UpdateCluster on a STOPPED cluster succeeded; expected ConflictException")
    assert code == "ConflictException", f"expected ConflictException, got {code}"

    # effect absent: shardInstanceCount unchanged while still STOPPED
    still_stopped = client.get_cluster(clusterArn=cluster_arn)["cluster"]
    assert still_stopped["status"] == "STOPPED", (
        f"expected status to remain STOPPED after the rejected update, got {still_stopped['status']!r}"
    )
    assert still_stopped["shardInstanceCount"] == 1, (
        f"expected shardInstanceCount to remain 1 after the rejected update, "
        f"got {still_stopped['shardInstanceCount']!r}"
    )

    # positive control: restart, then the identical update succeeds
    _start_cluster_when_ready(client, cluster_arn)
    _wait_for_status(client, cluster_arn, {"ACTIVE"})
    client.update_cluster(clusterArn=cluster_arn, shardInstanceCount=2)
    updated = _wait_for_shard_instance_count(client, cluster_arn, 2)
    assert updated["shardInstanceCount"] == 2, (
        f"expected the identical update to succeed once restarted, "
        f"got shardInstanceCount={updated['shardInstanceCount']!r}"
    )


# ===== helpers =====
def _wait_for_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_status = cluster["status"]
        if last_status in target_statuses:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={last_status}")


def _start_cluster_when_ready(client, cluster_arn, timeout_s=300.0, interval_s=15.0):
    """StartCluster can reject with ValidationException("...it's in use") for a few
    seconds right after GetCluster starts reporting STOPPED -- the status flips before
    the backend releases its internal lock. Bounded retry on that specific message only."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.start_cluster(clusterArn=cluster_arn)
            return
        except ClientError as e:
            err = e.response["Error"]
            transient = err["Code"] == "ValidationException" and "in use" in err.get("Message", "").lower()
            if transient and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _wait_for_shard_instance_count(client, cluster_arn, expected_count, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_cluster = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_cluster = cluster
        if cluster["status"] == "ACTIVE" and cluster.get("shardInstanceCount") == expected_count:
            return cluster
        time.sleep(interval_s)
    raise AssertionError(f"cluster never settled at shardInstanceCount={expected_count}, last={last_cluster}")


def _delete_cluster(client, cluster_arn, deadline_s=840.0):
    """Teardown: DeleteCluster refuses a cluster that is CREATING, UPDATING or STOPPED; start a
    STOPPED one and retry every 2 s to a deadline within the 900 s cleanup budget, then raise."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            client.delete_cluster(clusterArn=cluster_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if exc.response["Error"]["Code"] not in ("ConflictException", "ValidationException") \
                    or time.monotonic() >= deadline:
                raise
        try:
            if client.get_cluster(clusterArn=cluster_arn)["cluster"]["status"] == "STOPPED":
                client.start_cluster(clusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            # StartCluster briefly refuses a cluster that has only just reported STOPPED.
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
