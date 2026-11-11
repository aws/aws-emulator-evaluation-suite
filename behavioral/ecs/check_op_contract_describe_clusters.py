"""op-contract-describeClusters."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describeClusters"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeClusters echoes settings/tags/statistics and reports unknown names via failures[], not an exception."""
    ecs = ctx.client("ecs")

    name = ctx.unique_name("sim2real-behav-cluster-")
    ecs.create_cluster(
        clusterName=name,
        settings=[{"name": "containerInsights", "value": "disabled"}],
        tags=[{"key": "sim2real", "value": "yes"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))

    resp = ecs.describe_clusters(
        clusters=[name], include=["SETTINGS", "TAGS", "STATISTICS"]
    )
    assert resp["failures"] == [], f"expected no failures, got {resp['failures']}"
    cluster = resp["clusters"][0]
    assert cluster["clusterName"] == name, f"expected clusterName {name}, got {cluster['clusterName']}"
    assert cluster["status"] == "ACTIVE", f"expected status ACTIVE, got {cluster['status']}"
    assert {"name": "containerInsights", "value": "disabled"} in cluster["settings"], (
        f"expected containerInsights=disabled in settings, got {cluster['settings']}"
    )
    assert {"key": "sim2real", "value": "yes"} in cluster["tags"], (
        f"expected sim2real=yes tag, got {cluster['tags']}"
    )
    assert cluster["runningTasksCount"] == 0, f"expected 0 running tasks, got {cluster['runningTasksCount']}"
    assert cluster["pendingTasksCount"] == 0, f"expected 0 pending tasks, got {cluster['pendingTasksCount']}"
    stat_names = {s["name"] for s in cluster["statistics"]}
    assert "runningEC2TasksCount" in stat_names, (
        f"expected runningEC2TasksCount among reported statistics, got {stat_names}"
    )

    bogus_name = "sim2real-behav-cluster-does-not-exist-xyz"
    resp2 = ecs.describe_clusters(clusters=[bogus_name])
    assert resp2["clusters"] == [], f"expected no clusters, got {resp2['clusters']}"
    assert len(resp2["failures"]) == 1, f"expected exactly 1 failure, got {resp2['failures']}"
    assert resp2["failures"][0]["reason"] == "MISSING", (
        f"expected reason MISSING, got {resp2['failures'][0]['reason']}"
    )
    assert bogus_name in resp2["failures"][0]["arn"], (
        f"expected {bogus_name} in failure arn, got {resp2['failures'][0]['arn']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
