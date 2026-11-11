"""register-taskdef-unicode-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-taskdef-unicode-tags-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A unicode tag value on RegisterTaskDefinition survives DescribeTaskDefinition and
    ListTagsForResource byte-for-byte (no mangling, normalization, or truncation)."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-uni-")
    # ECS tag values are restricted to letters/numbers/spaces representable in UTF-8 plus
    # the punctuation + - = . _ : / @ — this exercises multi-byte UTF-8 letters (Japanese,
    # Spanish-accented Latin) without emoji, math symbols, or standalone combining marks
    # that the tag-value validator rejects outright.
    unicode_value = "日本語テスト-Ñoño-Café"

    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        containerDefinitions=[
            {"name": "c", "image": "public.ecr.aws/amazonlinux/amazonlinux:2023", "essential": True}
        ],
        tags=[{"key": "unicodeTag", "value": unicode_value}],
    )
    arn = resp["taskDefinition"]["taskDefinitionArn"]

    def _cleanup():
        ecs.deregister_task_definition(taskDefinition=arn)
        ecs.delete_task_definitions(taskDefinitions=[arn])

    ctx.on_cleanup(_cleanup)

    described = ecs.describe_task_definition(taskDefinition=arn, include=["TAGS"])
    described_tags = {t["key"]: t["value"] for t in described.get("tags", [])}
    assert described_tags.get("unicodeTag") == unicode_value, (
        f"unicode tag value mangled on DescribeTaskDefinition: {described_tags.get('unicodeTag')!r}"
    )

    listed = ecs.list_tags_for_resource(resourceArn=arn)
    listed_tags = {t["key"]: t["value"] for t in listed.get("tags", [])}
    assert listed_tags.get("unicodeTag") == unicode_value, (
        f"unicode tag value mangled on ListTagsForResource: {listed_tags.get('unicodeTag')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
