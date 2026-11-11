"""taskdef-delete-while-active-fails."""
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

CHECK = "taskdef-delete-while-active-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTaskDefinitions must reject a task definition that is still
    ACTIVE (it must be deregistered first) (overly-permissive check)."""
    ecs = ctx.client("ecs")
    td = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-"),
        containerDefinitions=DEFAULT_CONTAINER_DEFS,
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    arn = td["taskDefinitionArn"]

    def _cleanup_taskdef():
        # The run itself deregisters and deletes the revision; this only covers an
        # early failure, so a revision already INACTIVE or being deleted is fine.
        status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        if status == "ACTIVE":
            ecs.deregister_task_definition(taskDefinition=arn)
        if status != "DELETE_IN_PROGRESS":
            ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(_cleanup_taskdef)

    resp = ecs.delete_task_definitions(taskDefinitions=[arn])
    deleted = [d.get("taskDefinitionArn") for d in resp.get("taskDefinitions", [])]
    failures = resp.get("failures", [])
    assert arn not in deleted, (
        f"an ACTIVE task definition should not be deletable, but {arn} was deleted: {resp!r}"
    )
    assert failures, f"expected a failure entry for deleting an ACTIVE task definition, got {resp!r}"
    reason = failures[0].get("reason", "")
    expected_reason = (
        "The specified task definition is still in ACTIVE status. Please deregister the target and try again."
    )
    assert reason == expected_reason, (
        f"expected failure reason {expected_reason!r}, got {reason!r}"
    )

    still_active = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert still_active["status"] == "ACTIVE", (
        f"a rejected delete must leave the task definition ACTIVE, got {still_active['status']!r}"
    )

    ecs.deregister_task_definition(taskDefinition=arn)
    now_inactive = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert now_inactive["status"] == "INACTIVE", (
        f"deregistering the ACTIVE task definition should make it INACTIVE, got {now_inactive['status']!r}"
    )

    resp2 = ecs.delete_task_definitions(taskDefinitions=[arn])
    deleted2 = {d.get("taskDefinitionArn"): d for d in resp2.get("taskDefinitions", [])}
    assert arn in deleted2, (
        f"the identical delete call must succeed once the task definition is INACTIVE, got {resp2!r}"
    )
    # DeleteTaskDefinitions' own response carries the state the delete starts in.
    assert deleted2[arn]["status"] == "DELETE_IN_PROGRESS", (
        f"the DeleteTaskDefinitions response must report DELETE_IN_PROGRESS, got {deleted2[arn]['status']!r}"
    )
    # Independent read: DescribeTaskDefinition reflects the same DELETE_IN_PROGRESS state.
    now_deleting = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert now_deleting["status"] == "DELETE_IN_PROGRESS", (
        f"a successful delete must move the task definition to DELETE_IN_PROGRESS, got {now_deleting['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
