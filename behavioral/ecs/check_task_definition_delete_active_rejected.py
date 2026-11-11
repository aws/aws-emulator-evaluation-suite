"""task-definition-delete-active-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "task-definition-delete-active-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTaskDefinitions rejects a revision that is still ACTIVE; only INACTIVE
    revisions can be permanently deleted."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-fam-")

    registered = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "app", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "essential": True}
        ],
        tags=[{"key": "sim2real-owner", "value": "simparity"}],
    )["taskDefinition"]
    arn = registered["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))

    assert registered["status"] == "ACTIVE", f"expected a freshly registered task definition to be ACTIVE, got {registered['status']!r}"

    # Real AWS does not raise: it reports the ACTIVE revision in the batch's failures[] and
    # deletes nothing.
    resp = ecs.delete_task_definitions(taskDefinitions=[arn])
    assert resp["taskDefinitions"] == [], (
        f"deleting an ACTIVE task definition must not delete it, got {resp['taskDefinitions']}"
    )
    expected_failures = [{"arn": arn, "reason": "The specified task definition is still in ACTIVE status. Please deregister the target and try again."}]
    assert resp["failures"] == expected_failures, (
        f"expected failures {expected_failures!r}, got {resp['failures']!r}"
    )

    still_active = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert still_active["status"] == "ACTIVE", "task definition must not have been deleted while ACTIVE"

    # Now show the happy path: deregister first, then delete succeeds.
    ecs.deregister_task_definition(taskDefinition=arn)
    deleted = ecs.delete_task_definitions(taskDefinitions=[arn])
    assert not deleted.get("failures"), f"unexpected failures deleting INACTIVE definition: {deleted.get('failures')}"
    deleted_status = deleted["taskDefinitions"][0]["status"]
    assert deleted_status in ("INACTIVE", "DELETE_IN_PROGRESS"), (
        f"deleting an INACTIVE task definition must report INACTIVE or DELETE_IN_PROGRESS, got {deleted_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
