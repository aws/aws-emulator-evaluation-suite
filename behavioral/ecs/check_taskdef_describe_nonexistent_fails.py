"""taskdef-describe-nonexistent-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "taskdef-describe-nonexistent-fails"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Describing a task definition family/revision that never existed
    must fail (overly-permissive check)."""
    ecs = ctx.client("ecs")

    # Positive control: a task definition that really exists must describe
    # successfully, so the negative below cannot pass merely because the
    # target rejects every DescribeTaskDefinition call.
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    reg = ecs.register_task_definition(
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
    )
    arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))
    described = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert described["taskDefinitionArn"] == arn, f"positive control failed: {described}"

    bogus = f"{ctx.unique_name('sim2real-behav-ecs-taskdef-missing-')}:1"
    try:
        ecs.describe_task_definition(taskDefinition=bogus)
        raise AssertionError(f"DescribeTaskDefinition accepted the never-registered {bogus!r}")
    except ClientError as exc:
        error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    expected = ("ClientException", "Unable to describe task definition.")
    assert error == expected, f"expected {expected!r}, got {error!r}"


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
