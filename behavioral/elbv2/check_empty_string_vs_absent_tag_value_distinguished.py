"""empty-string-vs-absent-tag-value-distinguished."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "empty-string-vs-absent-tag-value-distinguished"
GROUP = "representation"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag explicitly added with an empty-string Value is stored and returned
    as that empty string (not dropped, not coerced to null) while a tag key
    that was never added does not spuriously appear in DescribeTags."""
    elbv2 = ctx.client("elbv2")

    name = _short_name(ctx, "tg")
    tg = elbv2.create_target_group(Name=name, TargetType="lambda")["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    empty_key = "empty-value-tag"
    populated_key = "populated-tag"
    never_added_key = "never-added-tag"

    elbv2.add_tags(
        ResourceArns=[tg_arn],
        Tags=[
            {"Key": empty_key, "Value": ""},
            {"Key": populated_key, "Value": "prod"},
        ],
    )

    described = elbv2.describe_tags(ResourceArns=[tg_arn])["TagDescriptions"][0]["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in described}

    assert empty_key in tag_map, f"empty-value tag missing entirely from {list(tag_map)}"
    assert tag_map[empty_key] == "", f"empty-value tag corrupted to {tag_map[empty_key]!r}"
    assert tag_map[populated_key] == "prod", f"populated tag corrupted to {tag_map[populated_key]!r}"
    assert never_added_key not in tag_map, "a tag key that was never added must not appear"


def _short_name(ctx, prefix: str) -> str:
    name = ctx.unique_name(f"{prefix}-").replace("_", "-")
    return name[:32].rstrip("-")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
