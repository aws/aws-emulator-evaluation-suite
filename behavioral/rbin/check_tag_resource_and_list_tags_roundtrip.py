"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "tags"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags assigned via TagResource show up verbatim in ListTagsForResource."""
    rbin = ctx.client("rbin")

    rule = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 6, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-tagroundtrip-"),
    )
    rule_id = rule["Identifier"]
    rule_arn = rule["RuleArn"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))

    before = rbin.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]
    assert before == [], f"expected no tags on a freshly created rule, got {before}"

    rbin.tag_resource(ResourceArn=rule_arn, Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "rbin-check"}])

    after = sorted(rbin.list_tags_for_resource(ResourceArn=rule_arn)["Tags"], key=lambda t: t["Key"])
    expected = [
        {"Key": "env", "Value": "sim2real"},
        {"Key": "owner", "Value": "rbin-check"},
    ]
    assert after == expected, f"expected tags {expected} verbatim after TagResource, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
