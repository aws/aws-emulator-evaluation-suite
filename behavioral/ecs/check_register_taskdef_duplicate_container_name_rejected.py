"""register-taskdef-duplicate-container-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-taskdef-duplicate-container-name-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition rejects two container definitions that share a name."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-dupname-")
    base_container = {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "memory": 128,
        "essential": True,
    }

    code, message = _refusal(
        lambda: ecs.register_task_definition(
            family=family,
            containerDefinitions=[dict(base_container), dict(base_container)],
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    assert message == "Container names must be unique within a task definition.", f"refusal message {message!r}"

    # Effect absent: no revision was ever registered under this family.
    families = ecs.list_task_definition_families(familyPrefix=family)["families"]
    assert family not in families, "a task definition family exists despite the rejected register call"

    # Positive control: distinct container names register successfully.
    good = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {**base_container, "name": "app-a"},
            {**base_container, "name": "app-b"},
        ],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, good["taskDefinitionArn"]))

    # Terminal assertion is an independent read (DescribeTaskDefinition), not the
    # RegisterTaskDefinition response itself.
    described = ecs.describe_task_definition(taskDefinition=good["taskDefinitionArn"])["taskDefinition"]
    assert described["status"] == "ACTIVE", f"expected ACTIVE, got {described['status']!r}"
    container_names = {c["name"] for c in described["containerDefinitions"]}
    assert container_names == {"app-a", "app-b"}, f"expected distinct names, got {container_names!r}"


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
