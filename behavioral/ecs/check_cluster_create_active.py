"""cluster-create-active."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cluster-create-active"
GROUP = 'cluster-lifecycle'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster produces a cluster that is immediately ACTIVE."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"),
        tags=[{"key": "sim2real", "value": "true"}],
    )["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    assert cluster["status"] == "ACTIVE", f"expected ACTIVE, got {cluster['status']}"

    desc = ecs.describe_clusters(clusters=[cluster["clusterName"]])
    assert len(desc["clusters"]) == 1, f"expected exactly 1 cluster, got {len(desc['clusters'])}"
    assert desc["clusters"][0]["status"] == "ACTIVE", (
        f"expected ACTIVE on independent read, got {desc['clusters'][0]['status']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
