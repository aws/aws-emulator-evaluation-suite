"""taskdef-describe-deregistered-still-visible."""
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

CHECK = "taskdef-describe-deregistered-still-visible"
GROUP = 'task-definition'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTaskDefinition still returns an INACTIVE (deregistered) task
    definition rather than treating it as gone."""
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    arn = td["taskDefinitionArn"]
    ecs.deregister_task_definition(taskDefinition=arn)

    desc = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert desc["status"] == "INACTIVE", f"expected INACTIVE, got {desc['status']}"
    assert desc["taskDefinitionArn"] == arn, f"expected arn {arn}, got {desc['taskDefinitionArn']}"
    assert desc["family"] == td["family"], f"expected family {td['family']}, got {desc['family']}"
    assert desc["revision"] == td["revision"], f"expected revision {td['revision']}, got {desc['revision']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
