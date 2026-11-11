"""task-definition-cpu-memory-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "task-definition-cpu-memory-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Task-level cpu/memory strings and container-level cpu/memory/memoryReservation integers come
    back from DescribeTaskDefinition with the same type and value: no rounding or conversion.
    """
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-cpumem-")

    # Deliberately non-round numbers: a target that coincidentally rounds or
    # unit-converts powers of two would still pass on 1024/2048/100/128/64.
    task_cpu = "347"
    task_memory = "919"
    container_cpu = 83
    container_memory = 251
    container_memory_reservation = 67

    register = ecs.register_task_definition(
        family=family,
        cpu=task_cpu,
        memory=task_memory,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "cpu": container_cpu,
                "memory": container_memory,
                "memoryReservation": container_memory_reservation,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real-check", "value": "task-definition-cpu-memory-numeric-precision-preserved"}],
    )
    task_def_arn = register["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    td = register["taskDefinition"]
    assert isinstance(td["cpu"], str), f"register response task cpu type: expected str, got {type(td['cpu'])}"
    assert td["cpu"] == task_cpu, f"register response task cpu: expected {task_cpu!r}, got {td['cpu']!r}"
    assert isinstance(td["memory"], str), f"register response task memory type: expected str, got {type(td['memory'])}"
    assert td["memory"] == task_memory, f"register response task memory: expected {task_memory!r}, got {td['memory']!r}"

    described = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
    assert isinstance(described["cpu"], str), f"described task cpu type: expected str, got {type(described['cpu'])}"
    assert described["cpu"] == task_cpu, f"described task cpu: expected {task_cpu!r}, got {described['cpu']!r}"
    assert isinstance(described["memory"], str), f"described task memory type: expected str, got {type(described['memory'])}"
    assert described["memory"] == task_memory, f"described task memory: expected {task_memory!r}, got {described['memory']!r}"

    container = described["containerDefinitions"][0]
    assert isinstance(container["cpu"], int), f"container cpu type: expected int, got {type(container['cpu'])}"
    assert container["cpu"] == container_cpu, f"container cpu: expected {container_cpu}, got {container['cpu']!r}"
    assert isinstance(container["memory"], int), f"container memory type: expected int, got {type(container['memory'])}"
    assert container["memory"] == container_memory, f"container memory: expected {container_memory}, got {container['memory']!r}"
    assert isinstance(container["memoryReservation"], int), (
        f"container memoryReservation type: expected int, got {type(container['memoryReservation'])}"
    )
    assert container["memoryReservation"] == container_memory_reservation, (
        f"container memoryReservation: expected {container_memory_reservation}, got {container['memoryReservation']!r}"
    )


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
