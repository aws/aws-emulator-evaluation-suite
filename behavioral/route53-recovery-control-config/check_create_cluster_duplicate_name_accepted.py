"""create-cluster-duplicate-name-accepted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-cluster-duplicate-name-accepted"
GROUP = "name-uniqueness"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """CreateCluster does not enforce ClusterName uniqueness: a second cluster with the same
    name as a live one succeeds rather than raising ConflictException, and the two stay
    independent (own ClusterArn, own describe_cluster, tagging one leaves the other untouched)."""
    client = ctx.client("route53-recovery-control-config")

    name = ctx.unique_name("sim2real-r53arc-dupcluster-")
    first_arn = _create_cluster_with_retry(client, name)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(client, first_arn))

    second_arn = _create_cluster_with_retry(client, name)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(client, second_arn))
    assert second_arn != first_arn, (second_arn, first_arn)

    # independent read: both are listed under the shared name, as distinct resources
    matches = {c["ClusterArn"] for c in client.list_clusters()["Clusters"] if c["Name"] == name}
    assert matches == {first_arn, second_arn}, (matches, first_arn, second_arn)

    # each is independently addressable under the shared name
    first_desc = client.describe_cluster(ClusterArn=first_arn)["Cluster"]["Name"]
    second_desc = client.describe_cluster(ClusterArn=second_arn)["Cluster"]["Name"]
    assert first_desc == name, (first_desc, name)
    assert second_desc == name, (second_desc, name)

    # independent identity, not just independent ARNs: tagging one does not tag the
    # other, despite the shared ClusterName
    client.tag_resource(ResourceArn=second_arn, Tags={"sim2real-probe": "second-only"})
    first_tags = client.list_tags_for_resource(ResourceArn=first_arn)["Tags"]
    second_tags = client.list_tags_for_resource(ResourceArn=second_arn)["Tags"]
    assert "sim2real-probe" not in first_tags, first_tags
    assert second_tags.get("sim2real-probe") == "second-only", second_tags


# ===== helpers =====
def _create_cluster_with_retry(client, name, timeout_s=60.0, interval_s=10.0):
    """CreateCluster, retrying ServiceQuotaExceededException for a bounded window —
    the account's 2-cluster quota may still be draining an async delete from a
    prior check's teardown."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.create_cluster(ClusterName=name, Tags={"sim2real": CHECK})[
                "Cluster"
            ]["ClusterArn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_cluster_and_wait(client, cluster_arn, timeout_s=300.0, interval_s=2.0) -> None:
    """Delete a cluster and block until it's actually gone — the account's cluster
    quota (2) is only freed once deletion truly completes, not when DeleteCluster
    returns, so the NEXT check that needs a fresh cluster must wait for this one."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.delete_cluster(ClusterArn=cluster_arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # refused while the cluster's control panels are still being deleted
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            client.describe_cluster(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
