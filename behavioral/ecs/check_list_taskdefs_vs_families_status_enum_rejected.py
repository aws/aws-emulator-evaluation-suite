"""list-taskdefs-vs-families-status-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "amazonlinux:2",
        "cpu": 10,
        "memory": 64,
        "essential": True,
    }
]

CHECK = "list-taskdefs-vs-families-status-enum-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecs']


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so an
    accepted call fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTaskDefinitions and ListTaskDefinitionFamilies reject an unknown status with
    InvalidParameterException naming each operation's own distinct status enum."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    reg = ecs.register_task_definition(
        family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS
    )["taskDefinition"]
    ctx.on_cleanup(lambda a=reg["taskDefinitionArn"]: ecs.delete_task_definitions(taskDefinitions=[a]))
    ctx.on_cleanup(lambda a=reg["taskDefinitionArn"]: ecs.deregister_task_definition(taskDefinition=a))

    active_arns = ecs.list_task_definitions(familyPrefix=family, status="ACTIVE").get(
        "taskDefinitionArns", []
    )
    assert active_arns == [reg["taskDefinitionArn"]], (
        f"positive control: ListTaskDefinitions status=ACTIVE must include the freshly "
        f"registered revision, got {active_arns!r}"
    )
    active_families = ecs.list_task_definition_families(familyPrefix=family, status="ACTIVE").get(
        "families", []
    )
    assert active_families == [family], (
        f"positive control: ListTaskDefinitionFamilies status=ACTIVE must include {family!r}, "
        f"got {active_families!r}"
    )

    code, message = _error(
        lambda: ecs.list_task_definitions(familyPrefix=family, status="BOGUS")
    )
    assert code == "InvalidParameterException", f"ListTaskDefinitions: expected InvalidParameterException, got {code!r}"
    expected_td_message = "Status should be one of [ACTIVE,INACTIVE,DELETE_IN_PROGRESS]"
    assert message == expected_td_message, (
        f"ListTaskDefinitions: expected message {expected_td_message!r}, got {message!r}"
    )

    code, message = _error(
        lambda: ecs.list_task_definition_families(familyPrefix=family, status="BOGUS")
    )
    assert code == "InvalidParameterException", f"ListTaskDefinitionFamilies: expected InvalidParameterException, got {code!r}"
    expected_families_message = "Status should be one of [ACTIVE,INACTIVE,ALL]"
    assert message == expected_families_message, (
        f"ListTaskDefinitionFamilies: expected message {expected_families_message!r}, got {message!r}"
    )

    # The rejected calls left the family's listed state unaffected.
    still_active_arns = ecs.list_task_definitions(familyPrefix=family, status="ACTIVE").get(
        "taskDefinitionArns", []
    )
    assert still_active_arns == [reg["taskDefinitionArn"]], (
        f"after the rejected status values, ListTaskDefinitions status=ACTIVE must still show "
        f"the revision, got {still_active_arns!r}"
    )
    still_active_families = ecs.list_task_definition_families(
        familyPrefix=family, status="ACTIVE"
    ).get("families", [])
    assert still_active_families == [family], (
        f"after the rejected status values, ListTaskDefinitionFamilies status=ACTIVE must still "
        f"show {family!r}, got {still_active_families!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
