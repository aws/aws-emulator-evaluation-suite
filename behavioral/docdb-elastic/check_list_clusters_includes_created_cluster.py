"""list-clusters-includes-created-cluster."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-clusters-includes-created-cluster"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster that reached ACTIVE via CreateCluster is discoverable through
    ListClusters with the matching clusterArn and status, including across pagination
    when maxResults is small enough to force multiple pages."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-list-")

    cluster_arn = client.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK},
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_cluster(client, cluster_arn))
    _wait_for_cluster_status(client, cluster_arn, {"ACTIVE"})

    found = _find_cluster_via_pagination(client, cluster_arn)
    assert found is not None, "created cluster not found via paginated ListClusters"
    assert found["clusterName"] == name.lower(), found["clusterName"]
    assert found["status"] == "ACTIVE", found["status"]


_TRANSIENT_STATUSES = {
    "CREATING", "STARTING", "STOPPING", "UPDATING", "DELETING",
    "MERGING", "MODIFYING", "SPLITTING", "COPYING", "MAINTENANCE",
}


def _wait_for_cluster_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
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


def _find_cluster_via_pagination(client, cluster_arn):
    next_token = None
    while True:
        kwargs = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_clusters(**kwargs)
        for entry in page.get("clusters", []):
            if entry["clusterArn"] == cluster_arn:
                return entry
        next_token = page.get("nextToken")
        if not next_token:
            return None


def _best_effort_delete_cluster(client, cluster_arn):
    try:
        client.delete_cluster(clusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
