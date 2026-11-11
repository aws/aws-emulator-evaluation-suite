"""cluster-delete-removes-from-active."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-delete-removes-from-active"
GROUP = 'cluster-lifecycle'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCluster transitions an empty cluster out of ACTIVE."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    cluster = ecs.create_cluster(
        clusterName=name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecs.delete_cluster(cluster=name)))
    assert cluster["status"] == "ACTIVE", f"expected ACTIVE on create, got {cluster['status']}"

    deleted = ecs.delete_cluster(cluster=name)["cluster"]
    assert deleted["status"] == "INACTIVE", (
        f"expected INACTIVE in DeleteCluster response, got {deleted['status']}"
    )

    desc = ecs.describe_clusters(clusters=[name])
    if desc["clusters"]:
        assert desc["clusters"][0]["status"] == "INACTIVE", (
            f"expected INACTIVE on independent describe, got {desc['clusters'][0]['status']}"
        )
    else:
        failures = desc.get("failures", [])
        assert len(failures) == 1, failures
        assert failures[0].get("reason") == "MISSING", failures[0]


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
