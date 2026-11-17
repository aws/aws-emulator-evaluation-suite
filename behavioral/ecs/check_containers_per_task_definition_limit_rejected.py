"""containers-per-task-definition-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "containers-per-task-definition-limit-rejected"
GROUP = "task-definition"
SERVICES = ["ecs"]

_MAX_CONTAINERS = 10


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _container(i: int) -> dict:
    return {"name": f"c{i}", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "memory": 32}


def _delete_task_definition(ecs, arn: str) -> None:
    """Deregister (INACTIVE) then permanently delete one task definition revision."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition accepts the fixed, non-adjustable ceiling of 10 container
    definitions and rejects an 11th without registering a new revision."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecsgw-taskdef-")

    at_limit = ecs.register_task_definition(
        family=family, containerDefinitions=[_container(i) for i in range(_MAX_CONTAINERS)]
    )["taskDefinition"]
    ctx.on_cleanup(lambda arn=at_limit["taskDefinitionArn"]: _delete_task_definition(ecs, arn))
    assert len(at_limit["containerDefinitions"]) == _MAX_CONTAINERS, (
        f"expected {_MAX_CONTAINERS} container definitions to register, "
        f"got {len(at_limit['containerDefinitions'])}"
    )
    assert at_limit["revision"] == 1, f"expected the first registration to be revision 1, got {at_limit['revision']!r}"

    code, message = _error(
        lambda: ecs.register_task_definition(
            family=family, containerDefinitions=[_container(i) for i in range(_MAX_CONTAINERS + 1)]
        )
    )
    assert code == "ClientException", (
        f"expected ClientException beyond the {_MAX_CONTAINERS}-container limit, got {code}: {message!r}"
    )
    assert message == "Too many containers.", f"unexpected message: {message!r}"

    revisions = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert len(revisions) == 1, (
        f"the rejected call must not have consumed a new revision, got {revisions!r}"
    )

    # Freed back to the documented ceiling, the identical shape still succeeds.
    at_limit_again = ecs.register_task_definition(
        family=family, containerDefinitions=[_container(i) for i in range(_MAX_CONTAINERS)]
    )["taskDefinition"]
    ctx.on_cleanup(
        lambda arn=at_limit_again["taskDefinitionArn"]: _delete_task_definition(ecs, arn)
    )
    assert at_limit_again["revision"] == 2, (
        f"expected the second accepted registration to be revision 2, got {at_limit_again['revision']!r}"
    )
    assert len(at_limit_again["containerDefinitions"]) == _MAX_CONTAINERS


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
