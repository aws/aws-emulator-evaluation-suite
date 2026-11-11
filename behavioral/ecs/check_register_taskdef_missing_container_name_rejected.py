"""register-taskdef-missing-container-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-taskdef-missing-container-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition rejects a container definition missing the required name field."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-taskdef-")

    code, message = _refusal(lambda: ecs.register_task_definition(
        family=family,
        containerDefinitions=[{
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "memory": 64,
            "essential": True,
        }],
    ))
    assert code == "ClientException", f"expected ClientException, got {code}"
    assert message == "Container.name should not be null or empty.", f"refusal message {message!r}"

    # effect absent: no revision was registered under this family
    arns = ecs.list_task_definitions(familyPrefix=family, status="ACTIVE")["taskDefinitionArns"]
    assert arns == [], f"expected no task definitions registered for {family}, found {arns}"

    # positive control: an otherwise-identical container definition WITH a name succeeds
    resp = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{
            "name": "app",
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "memory": 64,
            "essential": True,
        }],
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    taskdef_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, taskdef_arn))
    assert resp["taskDefinition"]["status"] == "ACTIVE", (
        f"expected ACTIVE for the named-container control, got {resp['taskDefinition']['status']!r}"
    )
    arns = ecs.list_task_definitions(familyPrefix=family, status="ACTIVE")["taskDefinitionArns"]
    assert arns == [taskdef_arn], f"expected only {taskdef_arn} listed for {family}, found {arns}"


def _refusal(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
