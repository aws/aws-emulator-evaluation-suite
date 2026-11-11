"""tag-resource-persists-and-untag-removes."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-persists-and-untag-removes"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster tags survive CREATING -> ACTIVE and show in ListTagsForResource;
    TagResource merges a new key alongside them rather than replacing them, and
    UntagResource removes only the named key."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-tag-")

    cluster_arn = client.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK, "sim2real-created-at": "creation"},
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(client, cluster_arn))
    _wait_for_status(client, cluster_arn, {"ACTIVE"})

    creation_tags = client.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert creation_tags.get("sim2real-check") == CHECK, (
        f"tag set at CreateCluster time did not survive to ACTIVE: {creation_tags}"
    )
    assert creation_tags.get("sim2real-created-at") == "creation", (
        f"second creation-time tag missing on the independent read: {creation_tags}"
    )

    client.tag_resource(resourceArn=cluster_arn, tags={"sim2real-added": "post-create"})
    merged_tags = client.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert merged_tags.get("sim2real-added") == "post-create", (
        f"TagResource did not add the new key: {merged_tags}"
    )
    assert merged_tags.get("sim2real-check") == CHECK, (
        f"TagResource clobbered a pre-existing creation-time tag instead of merging: {merged_tags}"
    )
    assert merged_tags.get("sim2real-created-at") == "creation", (
        f"TagResource clobbered a pre-existing creation-time tag instead of merging: {merged_tags}"
    )

    client.untag_resource(resourceArn=cluster_arn, tagKeys=["sim2real-added"])
    after_untag = client.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert "sim2real-added" not in after_untag, (
        f"UntagResource left the removed key behind: {after_untag}"
    )
    assert after_untag.get("sim2real-check") == CHECK, (
        f"UntagResource removed more than the named key: {after_untag}"
    )
    assert after_untag.get("sim2real-created-at") == "creation", (
        f"UntagResource removed more than the named key: {after_untag}"
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
        if last_status != "CREATING":
            raise AssertionError(
                f"cluster {cluster_arn} reached unexpected status {last_status!r} "
                f"while waiting for {target_statuses}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last status={last_status}")


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
