"""register-taskdef-malformed-container-definition-json-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-taskdef-malformed-container-definition-json-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterTaskDefinition with a container definition missing the required
    `image` field is rejected server-side, not silently coerced into a task
    definition revision."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-badtaskdef-")

    # Malformed: essential container with no image at all.
    code, message = _refusal(
        lambda: ecs.register_task_definition(
            family=family,
            containerDefinitions=[{"name": "app", "essential": True}],
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    assert message == "Container.image should not be null or empty.", f"refusal message {message!r}"

    # Effect absent: no revision was ever created for this family.
    listed = ecs.list_task_definitions(familyPrefix=family)["taskDefinitionArns"]
    assert listed == [], f"a task definition revision leaked despite rejection: {listed}"

    # Positive control: the same family with a complete container definition succeeds.
    resp = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "memory": 64,
                "command": ["sleep", "5"],
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    taskdef_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=taskdef_arn))
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[taskdef_arn]))
    status = resp["taskDefinition"]["status"]
    assert status == "ACTIVE", f"expected ACTIVE, got {status!r}"

    # Terminal read is independent of the mutating call: the new revision must be
    # visible at the destination through ListTaskDefinitions, not merely echoed back.
    listed_after = ecs.list_task_definitions(familyPrefix=family, status="ACTIVE")["taskDefinitionArns"]
    assert listed_after == [taskdef_arn], (
        f"expected exactly the new revision {taskdef_arn!r} listed for family {family!r}, "
        f"got {listed_after!r}"
    )


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
