"""create-rule-with-resource-tags-scopes-tag-level-rule."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-rule-with-resource-tags-scopes-tag-level-rule"
GROUP = "tags"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag-level rule created with ResourceTags reflects those exact resource tag
    key/value pairs on GetRule, distinct from a region-level rule's ExcludeResourceTags."""
    rbin = ctx.client("rbin")

    tag_rule_id = rbin.create_rule(
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 2, "RetentionPeriodUnit": "DAYS"},
        ResourceTags=[{"ResourceTagKey": "project", "ResourceTagValue": "sim2real"}],
        Description=ctx.unique_name("sim2real-rbin-resourcetags-"),
        Tags=[{"Key": "sim2real-check", "Value": "create-rule-with-resource-tags-scopes-tag-level-rule"}],
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=tag_rule_id))

    region_rule_id = rbin.create_rule(
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 2, "RetentionPeriodUnit": "DAYS"},
        ExcludeResourceTags=[{"ResourceTagKey": "do-not-retain", "ResourceTagValue": "true"}],
        Description=ctx.unique_name("sim2real-rbin-excludetags-"),
        Tags=[{"Key": "sim2real-check", "Value": "create-rule-with-resource-tags-scopes-tag-level-rule"}],
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=region_rule_id))

    tag_rule = rbin.get_rule(Identifier=tag_rule_id)
    expected_resource_tags = [{"ResourceTagKey": "project", "ResourceTagValue": "sim2real"}]
    assert tag_rule["ResourceTags"] == expected_resource_tags, (
        f"expected tag-level rule ResourceTags {expected_resource_tags}, got {tag_rule.get('ResourceTags')!r}"
    )
    assert tag_rule.get("ExcludeResourceTags", []) == [], (
        f"expected tag-level rule to carry no ExcludeResourceTags, got {tag_rule.get('ExcludeResourceTags')!r}"
    )

    region_rule = rbin.get_rule(Identifier=region_rule_id)
    expected_exclude_tags = [{"ResourceTagKey": "do-not-retain", "ResourceTagValue": "true"}]
    assert region_rule["ExcludeResourceTags"] == expected_exclude_tags, (
        f"expected region-level rule ExcludeResourceTags {expected_exclude_tags}, got {region_rule.get('ExcludeResourceTags')!r}"
    )
    assert region_rule.get("ResourceTags", []) == [], (
        f"expected region-level rule to carry no ResourceTags, got {region_rule.get('ResourceTags')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
