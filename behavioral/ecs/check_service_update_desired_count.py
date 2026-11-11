"""service-update-desired-count."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "service-update-desired-count"
GROUP = 'service-lifecycle'
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateService can change desiredCount on an existing service."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    svc = ecs.create_service(
        cluster=cluster["clusterName"],
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=0,
    )["service"]
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster["clusterName"], service=svc_name, force=True))

    updated = ecs.update_service(
        cluster=cluster["clusterName"], service=svc["serviceName"], desiredCount=3
    )["service"]
    assert updated["desiredCount"] == 3, (
        f"expected desiredCount 3 after update, got {updated['desiredCount']}"
    )

    described = ecs.describe_services(
        cluster=cluster["clusterName"], services=[svc_name]
    )["services"][0]
    assert described["desiredCount"] == 3, (
        f"expected desiredCount 3 on independent describe_services read, got {described['desiredCount']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
