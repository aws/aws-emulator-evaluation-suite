"""cluster-create-lifecycle-reaches-active."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-create-lifecycle-reaches-active"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster goes CREATING -> ACTIVE with the requested shard topology and a working
    endpoint and ARN, and TagResource/ListTagsForResource/UntagResource round-trip on it."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-create-")

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
    cluster = resp["cluster"]
    cluster_arn = cluster["clusterArn"]
    ctx.on_cleanup(lambda: _delete_with_retry(client, cluster_arn))
    assert cluster["status"] in ("CREATING", "ACTIVE")

    active = _wait_for_status(client, cluster_arn, {"ACTIVE"})
    assert active["clusterName"] == name.lower()
    assert active["shardCapacity"] == 2
    assert active["shardCount"] == 1
    assert active["clusterEndpoint"], "expected a non-empty clusterEndpoint on an ACTIVE cluster"
    assert len(active.get("shards", [])) == 1, f"expected 1 shard, got {active.get('shards')}"

    # the cleanup-ownership tag from create_cluster survives independently of the round-trip below
    created_tags = client.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert created_tags.get("sim2real-check") == CHECK

    # tag round-trip on a SEPARATE key, so untagging it never strips the ownership tag above
    client.tag_resource(resourceArn=cluster_arn, tags={"sim2real-roundtrip": CHECK})
    tags = client.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert tags.get("sim2real-roundtrip") == CHECK

    client.untag_resource(resourceArn=cluster_arn, tagKeys=["sim2real-roundtrip"])
    tags_after = client.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert "sim2real-roundtrip" not in tags_after
    assert tags_after.get("sim2real-check") == CHECK


# ===== helpers =====
_TRANSIENT_STATUSES = {
    "CREATING", "STARTING", "STOPPING", "UPDATING", "DELETING",
    "MERGING", "MODIFYING", "SPLITTING", "COPYING", "MAINTENANCE",
}


def _wait_for_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        cluster = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        last_status = cluster["status"]
        if last_status in target_statuses:
            return cluster
        if last_status not in _TRANSIENT_STATUSES:
            raise AssertionError(
                f"cluster {cluster_arn} reached unexpected terminal status "
                f"{last_status!r} while waiting for {target_statuses}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={last_status}")


def _delete_with_retry(client, cluster_arn, timeout_s=1800.0, interval_s=15.0):
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
