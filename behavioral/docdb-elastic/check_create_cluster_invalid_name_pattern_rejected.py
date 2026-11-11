"""create-cluster-invalid-name-pattern-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["docdb-elastic"]

_ADMIN_USER = "sim2realadmin"
_ADMIN_PASSWORD = "Sim2RealPassw0rd123"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster with a clusterName not starting with a letter fails with ValidationException "Invalid
    cluster name - <name>." and creates no cluster, while a compliant name creates a cluster that reaches ACTIVE."""
    client = ctx.client("docdb-elastic")
    bad_name = "1" + ctx.unique_name("sim2real-elastic-badname-")  # starts with a digit

    code, message = _error(
        lambda: client.create_cluster(
            clusterName=bad_name,
            authType="PLAIN_TEXT",
            adminUserName=_ADMIN_USER,
            adminUserPassword=_ADMIN_PASSWORD,
            shardCapacity=2,
            shardCount=1,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == f"Invalid cluster name - {bad_name}.", f"unexpected message: {message!r}"

    listing = client.list_clusters(maxResults=100)
    names = [c["clusterName"] for c in listing.get("clusters", [])]
    assert bad_name.lower() not in names, "a cluster was created despite the invalid name"

    good_name = ctx.unique_name("sim2real-elastic-goodname-")
    resp = client.create_cluster(
        clusterName=good_name,
        authType="PLAIN_TEXT",
        adminUserName=_ADMIN_USER,
        adminUserPassword=_ADMIN_PASSWORD,
        shardCapacity=2,
        shardCount=1,
        tags={"sim2real-check": CHECK},
    )
    cluster_arn = resp["cluster"]["clusterArn"]
    assert resp["cluster"]["clusterName"] == good_name.lower(), (
        f"expected clusterName {good_name.lower()!r}, got {resp['cluster']['clusterName']!r}"
    )
    ctx.on_cleanup(lambda: _delete_with_retry(client, cluster_arn))
    cluster = _wait_for_status(client, cluster_arn, {"ACTIVE"})
    assert cluster["status"] == "ACTIVE", f"expected ACTIVE, got {cluster['status']!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message); an unexpected success raises."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


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
