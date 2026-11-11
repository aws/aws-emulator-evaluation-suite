"""create-cluster-shard-count-exceeds-max-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-shard-count-exceeds-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster rejects a shardCount above the documented maximum of 32 with
    ValidationException and creates no cluster; an in-range shardCount is accepted, which
    shows the rejection is about the shard count rather than a blanket refusal."""
    client = ctx.client("docdb-elastic")
    bad_name = ctx.unique_name("sim2real-elastic-badcount-")

    code, message = _error(
        lambda: client.create_cluster(
            clusterName=bad_name,
            authType="PLAIN_TEXT",
            adminUserName=_ADMIN_USER,
            adminUserPassword=_ADMIN_PASSWORD,
            shardCapacity=2,
            shardCount=33,  # maximum is documented as 32
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "Invalid Input - '33'. ShardCount should be between 1 and 32.", (
        f"unexpected message: {message!r}"
    )

    listing = client.list_clusters(maxResults=100)
    names = [c["clusterName"] for c in listing.get("clusters", [])]
    assert bad_name.lower() not in names, "a cluster was created despite the out-of-range shardCount"

    good_name = ctx.unique_name("sim2real-elastic-goodcount-")
    resp = client.create_cluster(
        clusterName=good_name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
    )
    cluster_arn = resp["cluster"]["clusterArn"]
    assert resp["cluster"]["shardCount"] == 1, f"expected shardCount 1, got {resp['cluster']['shardCount']}"
    ctx.on_cleanup(lambda: _delete_cluster(client, cluster_arn))
    cluster = _wait_for_status(client, cluster_arn, {"ACTIVE"})
    assert cluster["status"] == "ACTIVE", f"expected ACTIVE, got {cluster['status']}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a rejected shardCount is the strongest signal available
    and must not be reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected ValidationException, but the call SUCCEEDED and returned {result!r}")


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
