"""cluster-lifecycle-active-to-inactive."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-lifecycle-active-to-inactive"
GROUP = "lifecycle"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster yields ACTIVE status; DeleteCluster transitions it to INACTIVE."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    created = ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])["cluster"]
    arn = created["clusterArn"]

    def _cleanup(cluster_arn=arn):
        try:
            ecs.delete_cluster(cluster=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    assert created["clusterName"] == name
    assert created["status"] == "ACTIVE", f"expected ACTIVE, got {created['status']}"

    described = ecs.describe_clusters(clusters=[arn])["clusters"]
    assert len(described) == 1
    assert described[0]["status"] == "ACTIVE"

    deleted = ecs.delete_cluster(cluster=arn)["cluster"]
    assert deleted["status"] == "INACTIVE", f"expected INACTIVE after delete, got {deleted['status']}"

    redescribed = ecs.describe_clusters(clusters=[arn])["clusters"]
    assert len(redescribed) == 1, f"expected the deleted cluster still visible via an independent describe, got {redescribed}"
    assert redescribed[0]["status"] == "INACTIVE", f"expected INACTIVE on independent read, got {redescribed[0]['status']}"

    listed = ecs.list_clusters()["clusterArns"]
    assert arn not in listed, "deleted cluster still appears in ListClusters"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
