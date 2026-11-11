"""op-contract-list-task-definitions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-task-definitions"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTaskDefinitions with a familyPrefix returns every revision of that family in
    ascending revision order (the documented default sort); a garbage nextToken is rejected
    with the generic ClientException (not InvalidParameterException)."""
    ecs = ctx.client("ecs")

    family = ctx.unique_name("sim2real-ecs-ltd-")
    rev1 = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 128, "essential": True, "command": ["sleep", "5"]}],
    )["taskDefinition"]
    rev2 = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 256, "essential": True, "command": ["sleep", "5"]}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, rev1["taskDefinitionArn"]))
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, rev2["taskDefinitionArn"]))
    assert rev1["revision"] == 1 and rev2["revision"] == 2, (rev1["revision"], rev2["revision"])

    arns = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert arns == [rev1["taskDefinitionArn"], rev2["taskDefinitionArn"]], arns

    arns_desc = ecs.list_task_definitions(familyPrefix=family, sort="DESC")["taskDefinitionArns"]
    assert arns_desc == [rev2["taskDefinitionArn"], rev1["taskDefinitionArn"]], arns_desc

    # Real ECS raises the generic ClientException for an undecodable pagination token (not
    # InvalidParameterException).
    code, message = _error(lambda: ecs.list_task_definitions(
        familyPrefix=family, nextToken="sim2real-not-a-real-pagination-token=="
    ))
    assert code == "ClientException", code
    expected_message = 'Invalid nextToken.'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
