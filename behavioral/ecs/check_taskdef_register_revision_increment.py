"""taskdef-register-revision-increment."""
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

CHECK = "taskdef-register-revision-increment"
GROUP = 'task-definition'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Successive RegisterTaskDefinition calls for the same family
    auto-increment the revision number starting at 1, and each revision is
    independently addressable by "family:revision" afterwards."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    reg_tags = [{"key": "sim2real", "value": "true"}]
    td1 = ecs.register_task_definition(
        family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS, tags=reg_tags
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td1["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td1["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))
    td2 = ecs.register_task_definition(
        family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS, tags=reg_tags
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=td2["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=td2["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))

    assert td1["revision"] == 1, f"expected first revision 1, got {td1['revision']}"
    assert td2["revision"] == 2, f"expected second revision 2, got {td2['revision']}"
    assert td1["family"] == td2["family"] == family, (
        f"expected both registrations to share family {family!r}, got "
        f"{td1['family']!r} and {td2['family']!r}"
    )

    # Independent read: address each revision explicitly by "family:revision"
    # rather than trusting the mutating calls' own echoed response.
    described1 = ecs.describe_task_definition(taskDefinition=f"{family}:1")["taskDefinition"]
    assert described1["revision"] == 1 and described1["family"] == family, (
        f"expected an independent describe of {family}:1 to resolve to revision 1 of {family}, "
        f"got revision={described1['revision']} family={described1['family']!r}"
    )
    described2 = ecs.describe_task_definition(taskDefinition=f"{family}:2")["taskDefinition"]
    assert described2["revision"] == 2 and described2["family"] == family, (
        f"expected an independent describe of {family}:2 to resolve to revision 2 of {family}, "
        f"got revision={described2['revision']} family={described2['family']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
