"""tag-resource-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-round-trip"
GROUP = "data-plane"
SERVICES = ["inspector2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a filter ARN is reflected exactly by ListTagsForResource."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-filter-tag-")

    created = inspector2.create_filter(
        action="NONE",
        name=name,
        filterCriteria={"severity": [{"comparison": "EQUALS", "value": "MEDIUM"}]},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: inspector2.delete_filter(arn=arn))

    before_tags = inspector2.list_tags_for_resource(resourceArn=arn)["tags"]
    assert before_tags == {}, f"expected no tags on a freshly created filter, got {before_tags}"

    inspector2.tag_resource(resourceArn=arn, tags={"Owner": "sim2real", "Stage": "test"})

    after_tags = inspector2.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after_tags == {"Owner": "sim2real", "Stage": "test"}, f"unexpected tags: {after_tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
