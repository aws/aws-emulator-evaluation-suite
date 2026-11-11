"""op-contract-register-task-definition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-register-task-definition"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition assigns sequential revisions within a family and returns
    status ACTIVE; registering a FARGATE-compatible definition with an incompatible
    networkMode (bridge) is rejected with ClientException and no new revision is created."""
    ecs = ctx.client("ecs")

    family = ctx.unique_name("sim2real-ecs-rtd-")
    rev1 = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 128, "essential": True, "command": ["sleep", "5"]}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, rev1["taskDefinitionArn"]))
    assert rev1["revision"] == 1, f"expected first revision 1, got {rev1['revision']}"
    assert rev1["status"] == "ACTIVE", f"expected status ACTIVE, got {rev1['status']!r}"
    assert rev1["taskDefinitionArn"].endswith(f"{family}:1"), (
        f"expected ARN to end with {family}:1, got {rev1['taskDefinitionArn']!r}")

    rev2 = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 256, "essential": True, "command": ["sleep", "5"]}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, rev2["taskDefinitionArn"]))
    assert rev2["revision"] == 2, f"expected second revision 2, got {rev2['revision']}"

    code, message = _error(lambda: ecs.register_task_definition(
        family=family,
        networkMode="bridge",
        requiresCompatibilities=["FARGATE"],
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 128, "essential": True, "command": ["sleep", "5"]}],
    ))
    assert code == "ClientException", f"expected ClientException for bridge+FARGATE, got {code!r}"
    assert message == "Fargate only supports network mode ‘awsvpc’.", message

    # No revision 3 was created by the rejected call.
    families = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert len(families) == 2, f"expected exactly 2 revisions ({family}:1, {family}:2), found {families}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, because an emulator accepting input real AWS refuses must fail loudly rather than
    read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
