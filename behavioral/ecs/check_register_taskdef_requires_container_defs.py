"""register-taskdef-requires-container-defs."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-taskdef-requires-container-defs"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises,
    because accepting input AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition rejects an empty containerDefinitions list and leaves the family
    undescribable; the same family registers once a real container definition is supplied."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-empty-")

    err = _client_error(lambda: ecs.register_task_definition(family=family, containerDefinitions=[]))
    assert err.get("Code") == "ClientException", f"unexpected error code: {err}"
    assert err.get("Message") == "Container list cannot be empty.", err

    # independent read: the rejected call created nothing describable under this family.
    describe_err = _client_error(lambda: ecs.describe_task_definition(taskDefinition=family))
    assert describe_err.get("Code") == "ClientException", (
        f"expected no task definition for {family!r} after the rejected register, "
        f"got {describe_err}"
    )
    assert describe_err.get("Message") == "Unable to describe task definition.", describe_err

    # positive control: the identical family with a real container definition registers fine.
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "memory": 128,
            }
        ],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))
    assert td["status"] == "ACTIVE", f"expected ACTIVE, got {td['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
