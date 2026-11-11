"""cluster-stop-start-lifecycle."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-stop-start-lifecycle"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"

_TRANSIENT_STATUSES = {
    "CREATING", "STARTING", "STOPPING", "UPDATING", "DELETING",
    "MERGING", "MODIFYING", "SPLITTING", "COPYING", "MAINTENANCE",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopCluster drives ACTIVE -> STOPPED and StartCluster drives it back to ACTIVE, each confirmed on
    GetCluster and ListClusters, with the shard topology unchanged."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-stopstart-")

    resp = client.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_admin_password(ctx),
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK},
    )
    cluster_arn = resp["cluster"]["clusterArn"]
    _register_cluster_cleanup(ctx, cluster_arn)
    _wait_for_status(client, cluster_arn, {"ACTIVE"})

    client.stop_cluster(clusterArn=cluster_arn)
    stopped = _wait_for_status(client, cluster_arn, {"STOPPED"})
    assert stopped["status"] == "STOPPED", f"expected STOPPED, got {stopped['status']!r}"
    listed_stopped = _find_in_list_clusters(client, cluster_arn)
    assert listed_stopped is not None, "stopped cluster missing from ListClusters"
    assert listed_stopped["status"] == "STOPPED", (
        f"ListClusters reports {listed_stopped['status']!r} for a cluster GetCluster reports STOPPED"
    )

    client.start_cluster(clusterArn=cluster_arn)
    active_again = _wait_for_status(client, cluster_arn, {"ACTIVE"})
    assert active_again["clusterArn"] == cluster_arn, (
        f"expected {cluster_arn}, got {active_again['clusterArn']!r}"
    )
    assert active_again["shardCapacity"] == 2, (
        f"shardCapacity drifted across stop/start: expected 2, got {active_again['shardCapacity']!r}"
    )
    assert active_again["shardCount"] == 1, (
        f"shardCount drifted across stop/start: expected 1, got {active_again['shardCount']!r}"
    )
    listed_active = _find_in_list_clusters(client, cluster_arn)
    assert listed_active is not None, "restarted cluster missing from ListClusters"
    assert listed_active["status"] == "ACTIVE", (
        f"ListClusters reports {listed_active['status']!r} for a cluster GetCluster reports ACTIVE"
    )


# ===== helpers =====
def _admin_password(ctx):
    suffix = re.sub(r"[^A-Za-z0-9]", "", ctx.unique_name("x"))[:12]
    return f"S1mparityPw{suffix}"


def _wait_for_status(client, cluster_arn, target_statuses, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_cluster(clusterArn=cluster_arn)["cluster"]
        if last["status"] in target_statuses:
            return last
        if last["status"] not in _TRANSIENT_STATUSES:
            raise AssertionError(
                f"cluster {cluster_arn} reached unexpected terminal status {last['status']!r} "
                f"while waiting for {target_statuses}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {cluster_arn} did not reach {target_statuses} within {timeout_s}s "
        f"(last status={last['status'] if last else None})"
    )


def _find_in_list_clusters(client, cluster_arn):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_clusters(**kwargs)
        for entry in page.get("clusters", []):
            if entry["clusterArn"] == cluster_arn:
                return entry
        next_token = page.get("nextToken")
        if not next_token:
            return None


def _register_cluster_cleanup(ctx, cluster_arn):
    def _cleanup():
        client = ctx.client("docdb-elastic")
        # The suite's cleanup budget is 900 s; the delete retries inside it.
        deadline = time.monotonic() + 850.0
        while time.monotonic() < deadline:
            try:
                client.delete_cluster(clusterArn=cluster_arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code == "ConflictException":
                    try:
                        status = client.get_cluster(clusterArn=cluster_arn)["cluster"]["status"]
                    except ClientError as err:
                        if err.response["Error"]["Code"] != "ResourceNotFoundException":
                            raise
                        return
                    if status == "STOPPED":
                        try:
                            client.start_cluster(clusterArn=cluster_arn)
                        except ClientError as err:
                            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                                raise
                    time.sleep(2.0)
                    continue
                raise
        raise RuntimeError(f"elastic cluster {cluster_arn} was still refusing deletion after 850s")

    ctx.on_cleanup(_cleanup)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
