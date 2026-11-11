"""op-contract-list-task-definition-families."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-list-task-definition-families"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTaskDefinitionFamilies filtered by familyPrefix returns exactly the matching
    family; an invalid (non-decodable) nextToken is rejected with InvalidParameterException
    rather than silently returning an empty/garbage page."""
    ecs = ctx.client("ecs")

    family = ctx.unique_name("sim2real-ecs-ltdf-")
    td_arn = ecs.register_task_definition(
        family=family,
        containerDefinitions=[{"name": "app", "image": "public.ecr.aws/docker/library/busybox:1.36",
                                "memory": 128, "essential": True, "command": ["sleep", "5"]}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    resp = ecs.list_task_definition_families(familyPrefix=family)
    assert resp["families"] == [family], resp["families"]

    # Positive control: a syntactically-empty pagination request succeeds cleanly.
    resp2 = ecs.list_task_definition_families(familyPrefix=family, maxResults=10)
    assert resp2["families"] == [family], resp2["families"]

    # Negative: a bogus nextToken is rejected server-side, the request is NOT silently accepted.
    # Real ECS raises the generic ClientException for an undecodable pagination token (not
    # InvalidParameterException).
    code, message = _error(lambda: ecs.list_task_definition_families(
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
