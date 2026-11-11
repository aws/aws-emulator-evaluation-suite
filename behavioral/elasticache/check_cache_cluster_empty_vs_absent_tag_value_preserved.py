"""cache-cluster-empty-vs-absent-tag-value-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cache-cluster-empty-vs-absent-tag-value-preserved"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty-string tag value stays present as "" in ListTagsForResource, distinct from absent:
    after RemoveTagsFromResource drops a sibling key, that key is gone and the empty tag remains.
    """
    ec = ctx.client("elasticache")
    # A parameter group stands in for a cluster: the tagging API is shared across resource types.
    name = ctx.unique_name("sim2real-behav-pg-")
    created = ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="sim2real empty-vs-absent tag check",
    )
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=name))
    arn = created["CacheParameterGroup"]["ARN"]

    ec.add_tags_to_resource(
        ResourceName=arn,
        Tags=[
            {"Key": "alpha-empty", "Value": ""},
            {"Key": "beta-present", "Value": "present-value"},
        ],
    )
    tags = {t["Key"]: t["Value"] for t in ec.list_tags_for_resource(ResourceName=arn)["TagList"]}
    assert "alpha-empty" in tags and tags["alpha-empty"] == "", (
        f"explicit empty-string tag not preserved as empty, got {tags.get('alpha-empty')!r}"
    )
    assert tags.get("beta-present") == "present-value", (
        f"expected beta-present tag value 'present-value', got {tags.get('beta-present')!r}"
    )

    ec.remove_tags_from_resource(ResourceName=arn, TagKeys=["beta-present"])
    tags_after = {t["Key"]: t["Value"] for t in ec.list_tags_for_resource(ResourceName=arn)["TagList"]}

    assert "beta-present" not in tags_after, (
        "removed tag key is still present after RemoveTagsFromResource"
    )
    assert "alpha-empty" in tags_after and tags_after["alpha-empty"] == "", (
        "empty-string tag became indistinguishable from an absent tag after an "
        f"unrelated RemoveTagsFromResource call, got {tags_after.get('alpha-empty')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
