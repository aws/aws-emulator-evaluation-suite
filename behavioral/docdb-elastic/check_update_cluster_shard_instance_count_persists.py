"""update-cluster-shard-instance-count-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-cluster-shard-instance-count-persists"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"

_TRANSIENT_STATUSES = {
    "CREATING", "STARTING", "STOPPING", "UPDATING", "DELETING",
    "MERGING", "MODIFYING", "SPLITTING", "COPYING", "MAINTENANCE",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCluster changing shardInstanceCount drives ACTIVE -> UPDATING -> ACTIVE, and
    GetCluster afterwards reflects the new shardInstanceCount (not the value the cluster
    was created with)."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-update-")

    resp = client.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        shardInstanceCount=1,
        tags={"sim2real-check": CHECK},
    )
    cluster_arn = resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_with_retry(client, cluster_arn))
    before = _wait_for_status(client, cluster_arn, {"ACTIVE"})
    assert before["shardInstanceCount"] == 1, f"expected shardInstanceCount=1 right after create, got {before}"

    client.update_cluster(clusterArn=cluster_arn, shardInstanceCount=2)
    after = _wait_for_shard_instance_count(client, cluster_arn, 2)
    assert after["status"] == "ACTIVE", f"expected status=ACTIVE once settled, got {after}"
    assert after["shardInstanceCount"] == 2, f"expected shardInstanceCount=2, got {after}"


def _wait_for_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_cluster = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_cluster = cluster
        if cluster["status"] in target_statuses:
            return cluster
        if cluster["status"] not in _TRANSIENT_STATUSES:
            raise AssertionError(
                f"cluster {cluster_arn} reached unexpected terminal status "
                f"{cluster['status']!r} while waiting for {target_statuses}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last_cluster}")


def _wait_for_shard_instance_count(client, cluster_arn, expected_count, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_cluster = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_cluster = cluster
        if cluster["status"] == "ACTIVE" and cluster.get("shardInstanceCount") == expected_count:
            return cluster
        if cluster["status"] not in _TRANSIENT_STATUSES and cluster["status"] != "ACTIVE":
            raise AssertionError(
                f"cluster {cluster_arn} reached unexpected terminal status "
                f"{cluster['status']!r} while waiting for shardInstanceCount={expected_count}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"cluster never settled at shardInstanceCount={expected_count}, last={last_cluster}")


def _delete_cluster_with_retry(client, cluster_arn, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.delete_cluster(clusterArn=cluster_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException":
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
