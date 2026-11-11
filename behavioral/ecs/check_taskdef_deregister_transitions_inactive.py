"""taskdef-deregister-transitions-inactive."""
from __future__ import annotations

from behavioral_harness import tags

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "amazonlinux:2",
        "cpu": 10,
        "memory": 64,
        "essential": True,
    }
]

CHECK = "taskdef-deregister-transitions-inactive"
GROUP = 'task-definition'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterTaskDefinition moves a task definition from ACTIVE to
    INACTIVE without deleting it, and an independent read confirms it."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    td = ecs.register_task_definition(family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS)["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    arn = td["taskDefinitionArn"]
    assert td["status"] == "ACTIVE", f"expected ACTIVE on register, got {td['status']}"

    dereg = ecs.deregister_task_definition(taskDefinition=arn)["taskDefinition"]
    assert dereg["status"] == "INACTIVE", f"expected INACTIVE, got {dereg['status']}"

    # The terminal assertion must be an independent read, not the mutating call's
    # own response -- a target could echo INACTIVE back without persisting anything.
    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described["status"] == "INACTIVE", (
        f"independent DescribeTaskDefinition read must also show INACTIVE, got {described['status']}"
    )
    assert described["taskDefinitionArn"] == arn, described["taskDefinitionArn"]
    assert described["family"] == family, described["family"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
