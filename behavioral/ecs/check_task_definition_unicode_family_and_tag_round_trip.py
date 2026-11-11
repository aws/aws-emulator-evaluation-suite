"""task-definition-unicode-family-and-tag-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "task-definition-unicode-family-and-tag-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A mixed-case family name round-trips exactly, and a multi-byte unicode tag value (ECS limits
    family to ASCII) comes back byte-identical through DescribeTaskDefinition(include=TAGS).
    """
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-UniFam_Test-")

    register = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "memory": 64,
                "essential": True,
            }
        ],
    )
    task_def_arn = register["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    assert register["taskDefinition"]["family"] == family, (
        f"family mangled on RegisterTaskDefinition: expected {family!r}, "
        f"got {register['taskDefinition']['family']!r}"
    )

    # ECS tag values only accept UTF-8 letters, spaces, numbers and the characters
    # _.:/=+@- ; multi-byte *letters* (accented Latin, CJK) are valid, but emoji /
    # other symbol code points are rejected with a ValidationException, so this
    # exercises unicode round-tripping without straying outside the allowed set.
    unicode_value = "héllo 世界 naïve café_日本語-test"
    ecs.tag_resource(
        resourceArn=task_def_arn,
        tags=[{"key": "unicode-tag", "value": unicode_value}],
    )

    described = ecs.describe_task_definition(taskDefinition=task_def_arn, include=["TAGS"])
    assert described["taskDefinition"]["family"] == family, (
        f"family mangled on DescribeTaskDefinition: expected {family!r}, "
        f"got {described['taskDefinition']['family']!r}"
    )

    tags_by_key = {t["key"]: t["value"] for t in described["tags"]}
    assert tags_by_key.get("unicode-tag") == unicode_value, (
        f"unicode tag value mangled on DescribeTaskDefinition: expected {unicode_value!r}, "
        f"got {tags_by_key.get('unicode-tag')!r}"
    )


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
