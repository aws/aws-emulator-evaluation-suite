"""service-create-requires-valid-cluster."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-create-requires-valid-cluster"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "amazonlinux:2",
        "cpu": 10,
        "memory": 64,
        "essential": True,
    }
]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateService against a nonexistent cluster fails with ClusterNotFoundException "Cluster not found."
    and creates no cluster, and the same call succeeds with an ACTIVE service once the cluster exists.
    """
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda a=td_arn: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td_arn: ecs.deregister_task_definition(taskDefinition=a))

    cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-missing-")
    service_name = ctx.unique_name("sim2real-behav-ecs-svc-")

    # independent read, via a different operation than the one under test,
    # before any mutation: the cluster genuinely does not exist yet.
    pre = ecs.describe_clusters(clusters=[cluster_name])
    assert not pre["clusters"], f"cluster unexpectedly pre-existed: {pre['clusters']}"
    assert pre["failures"] and pre["failures"][0]["reason"] == "MISSING", (
        f"expected DescribeClusters to report MISSING, got {pre['failures']}"
    )

    code = message = None
    try:
        ecs.create_service(
            cluster=cluster_name,
            serviceName=service_name,
            taskDefinition=td_arn,
            desiredCount=0,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError("create_service against a nonexistent cluster unexpectedly succeeded")
    assert code == "ClusterNotFoundException", f"unexpected error code: {code}"
    assert message == "Cluster not found.", f"unexpected error message: {message!r}"

    # effect absent, independent read again: CreateService must not have
    # side-effected the cluster into existing.
    post = ecs.describe_clusters(clusters=[cluster_name])
    assert not post["clusters"], f"cluster came into existence after the rejected call: {post['clusters']}"

    # restore: the cluster now genuinely exists...
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    # ...and the identical call now succeeds.
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td_arn,
        desiredCount=0,
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    # terminal read: independent of the mutating call, at the destination.
    desc = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"]
    assert desc and desc[0]["status"] == "ACTIVE", f"service not visible/active after creation: {desc}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
