"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "data-plane"
SERVICES = ["inspector2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested tag key, leaving the others intact."""
    inspector2 = ctx.client("inspector2")
    name = ctx.unique_name("sim2real-filter-untag-")

    created = inspector2.create_filter(
        action="NONE",
        name=name,
        filterCriteria={"severity": [{"comparison": "EQUALS", "value": "MEDIUM"}]},
        tags={"Owner": "sim2real", "Stage": "test"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: inspector2.delete_filter(arn=arn))

    before_tags = inspector2.list_tags_for_resource(resourceArn=arn)["tags"]
    assert before_tags == {"Owner": "sim2real", "Stage": "test"}, (
        f"expected both tags present before untag, got {before_tags}"
    )

    inspector2.untag_resource(resourceArn=arn, tagKeys=["Stage"])

    after_tags = inspector2.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after_tags == {"Owner": "sim2real"}, f"expected only Owner tag remaining, got {after_tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
