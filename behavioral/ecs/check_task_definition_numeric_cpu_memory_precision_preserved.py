"""task-definition-numeric-cpu-memory-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "task-definition-numeric-cpu-memory-precision-preserved"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Task-level string cpu/memory and container-level integer soft/hard memory limits round-trip exactly, unrounded and untyped-coerced."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-numeric-")

    # Deliberately odd, non-power-of-two numbers so a coercion/rounding bug is visible.
    task_cpu = "257"
    task_memory = "513"
    container_cpu = 101
    container_memory_hard = 201
    container_memory_soft = 99

    register_resp = ecs.register_task_definition(
        family=family,
        cpu=task_cpu,
        memory=task_memory,
        containerDefinitions=[
            {
                "name": "app",
                "image": "amazonlinux:2",
                "cpu": container_cpu,
                "memory": container_memory_hard,
                "memoryReservation": container_memory_soft,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    task_def_arn = register_resp["taskDefinition"]["taskDefinitionArn"]

    def _cleanup():
        ecs.deregister_task_definition(taskDefinition=task_def_arn)
        ecs.delete_task_definitions(taskDefinitions=[task_def_arn])

    ctx.on_cleanup(_cleanup)

    described = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]

    assert isinstance(described["cpu"], str), f"task cpu type coerced: {type(described['cpu'])}"
    assert described["cpu"] == task_cpu, f"task cpu changed: {described['cpu']!r} != {task_cpu!r}"
    assert isinstance(described["memory"], str), f"task memory type coerced: {type(described['memory'])}"
    assert described["memory"] == task_memory, f"task memory changed: {described['memory']!r} != {task_memory!r}"

    container = described["containerDefinitions"][0]
    assert container["cpu"] == container_cpu, f"container cpu changed: {container['cpu']!r} != {container_cpu!r}"
    assert container["memory"] == container_memory_hard, (
        f"container memory (hard limit) changed: {container['memory']!r} != {container_memory_hard!r}"
    )
    assert container["memoryReservation"] == container_memory_soft, (
        f"container memoryReservation (soft limit) changed: {container['memoryReservation']!r} != {container_memory_soft!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
