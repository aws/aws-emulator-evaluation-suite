"""cluster-create-idempotent-by-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cluster-create-idempotent-by-name"
GROUP = 'cluster-lifecycle'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling CreateCluster again with the same name returns the existing
    cluster (same ARN) rather than creating a duplicate or erroring."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    first = ecs.create_cluster(
        clusterName=name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]
    ctx.on_cleanup(lambda c=first: ecs.delete_cluster(cluster=c["clusterName"]))
    second = ecs.create_cluster(clusterName=name)["cluster"]
    assert second["clusterArn"] == first["clusterArn"], (
        "re-creating a cluster with the same name should return the same "
        f"clusterArn, got {first['clusterArn']} vs {second['clusterArn']}"
    )
    assert second["status"] == "ACTIVE", f"expected ACTIVE, got {second['status']}"

    # Independent read at the destination: the two CreateCluster calls must have
    # produced exactly one cluster, not a second one that merely echoes the first's ARN.
    described = ecs.describe_clusters(clusters=[name])["clusters"]
    assert len(described) == 1, (
        f"expected exactly one cluster named {name!r}, found {len(described)}"
    )
    assert described[0]["clusterArn"] == first["clusterArn"], (
        "describe_clusters should resolve the same clusterArn created above, "
        f"got {described[0]['clusterArn']} vs {first['clusterArn']}"
    )
    assert described[0]["status"] == "ACTIVE", described[0]["status"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
