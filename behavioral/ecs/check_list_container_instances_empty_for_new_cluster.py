"""list-container-instances-empty-for-new-cluster."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-container-instances-empty-for-new-cluster"
GROUP = 'container-instance'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created, empty cluster reports zero container instances."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"),
        tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))

    arns = ecs.list_container_instances(cluster=cluster["clusterName"]).get(
        "containerInstanceArns", []
    )
    assert arns == [], f"expected no container instances, got {arns}"

    described = ecs.describe_clusters(clusters=[cluster["clusterArn"]])["clusters"][0]
    count = described["registeredContainerInstancesCount"]
    assert count == 0, f"expected registeredContainerInstancesCount 0, got {count}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
