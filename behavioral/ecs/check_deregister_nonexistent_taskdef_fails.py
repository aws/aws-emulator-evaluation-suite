"""deregister-nonexistent-taskdef-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-nonexistent-taskdef-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterTaskDefinition makes a real revision INACTIVE as described, while on a
    never-registered family:revision it is refused ClientException 'Unable to describe task
    definition.'."""
    ecs = ctx.client("ecs")

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    registered = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
    )["taskDefinition"]
    arn = registered["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    assert registered["status"] == "ACTIVE", f"expected ACTIVE, got {registered['status']}"

    deregistered = ecs.deregister_task_definition(taskDefinition=arn)["taskDefinition"]
    assert deregistered["status"] == "INACTIVE", (
        f"positive control failed: expected INACTIVE, got {deregistered['status']}"
    )

    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described["status"] == "INACTIVE", (
        f"independent read disagrees with mutation: expected INACTIVE, got {described['status']}"
    )

    bogus = f"{ctx.unique_name('sim2real-behav-ecs-taskdef-missing-')}:1"
    try:
        result = ecs.deregister_task_definition(taskDefinition=bogus)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")
    assert code == "ClientException", f"expected ClientException, got {code}"
    assert message == "Unable to describe task definition.", f"unexpected message: {message!r}"


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
