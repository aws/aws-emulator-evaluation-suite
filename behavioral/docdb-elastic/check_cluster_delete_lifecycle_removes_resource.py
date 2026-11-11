"""cluster-delete-lifecycle-removes-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-delete-lifecycle-removes-resource"
GROUP = "state"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteCluster on an ACTIVE cluster, GetCluster fails with ResourceNotFoundException, ListClusters
    omits it, and a second DeleteCluster fails with ResourceNotFoundException "Unable to find the cluster"."""
    client = ctx.client("docdb-elastic")
    name = ctx.unique_name("sim2real-elastic-delete-")

    resp = client.create_cluster(
        clusterName=name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK},
    )
    cluster_arn = resp["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(client, cluster_arn, time.monotonic() + _TEARDOWN_S))
    _wait_for_status(client, cluster_arn, {"ACTIVE"})

    client.delete_cluster(clusterArn=cluster_arn)
    _wait_for_absent(client, cluster_arn)

    names = [c["clusterName"] for c in client.list_clusters(maxResults=100).get("clusters", [])]
    assert name.lower() not in names, "deleted cluster still appears in ListClusters"

    try:
        client.delete_cluster(clusterArn=cluster_arn)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException re-deleting a dead clusterArn, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == "Unable to find the cluster", f"unexpected message: {message!r}"
    else:
        raise AssertionError("DeleteCluster on an already-deleted clusterArn unexpectedly succeeded")


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


def _wait_for_absent(client, cluster_arn, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.get_cluster(clusterArn=cluster_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("cluster was not deleted within timeout")


# Inside the 1800 s docdb-elastic cleanup budget.
_TEARDOWN_S = 1680.0
# DeleteCluster and StartCluster answer ValidationException with these messages while the cluster is in a
# state that refuses them; a STOPPED elastic cluster cannot be deleted until it is started.
_REFUSED_FOR_STATE = (
    "Can't delete the cluster because it is in ",
    "Can't start the cluster as it's currently in state",
)


def _refused_for_state(exc):
    err = exc.response["Error"]
    message = err.get("Message") or ""
    return err["Code"] == "ConflictException" or (
        err["Code"] == "ValidationException" and message.startswith(_REFUSED_FOR_STATE)
    )


def _delete_cluster(client, cluster_arn, deadline):
    """Delete the cluster, starting it first when STOPPED, and poll every 2 s until GetCluster answers
    not-found; a state refusal is retried until ``deadline``. A cluster gone is done; any other failure, or the
    deadline passing, raises."""
    status = None
    while True:
        try:
            status = client.get_cluster(clusterArn=cluster_arn)["cluster"]["status"]
            if status == "STOPPED":
                client.start_cluster(clusterArn=cluster_arn)
            elif status != "DELETING":
                client.delete_cluster(clusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if not _refused_for_state(exc):
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster_arn} still {status!r} at the teardown deadline; not deleted")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
