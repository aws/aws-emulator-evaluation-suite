"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "tags"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named tag key and leaves the others intact."""
    rbin = ctx.client("rbin")

    rule = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 6, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-untag-"),
    )
    rule_id = rule["Identifier"]
    rule_arn = rule["RuleArn"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))

    rbin.tag_resource(ResourceArn=rule_arn, Tags=[{"Key": "keep", "Value": "1"}, {"Key": "remove", "Value": "2"}])
    before_keys = {t["Key"] for t in rbin.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]}
    assert before_keys == {"keep", "remove"}, f"expected both tags present before untag, got {before_keys}"

    rbin.untag_resource(ResourceArn=rule_arn, TagKeys=["remove"])

    remaining = rbin.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]
    assert remaining == [{"Key": "keep", "Value": "1"}], (
        f"expected only 'keep' tag to remain after untagging 'remove', got {remaining}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
