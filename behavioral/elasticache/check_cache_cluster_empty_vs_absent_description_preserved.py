"""cache-cluster-empty-vs-absent-description-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cache-cluster-empty-vs-absent-description-preserved"
GROUP = "representation"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty-string Description on CreateCacheParameterGroup reads back as a single space, while
    a non-empty description on a sibling group reads back unchanged. CacheCluster has no
    Description field, so parameter groups stand in for it."""
    ec = ctx.client("elasticache")
    empty_name = ctx.unique_name("sim2real-emptydesc-")
    filled_name = ctx.unique_name("sim2real-filleddesc-")

    ec.create_cache_parameter_group(
        CacheParameterGroupName=empty_name,
        CacheParameterGroupFamily="redis7",
        Description="",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=empty_name))

    ec.create_cache_parameter_group(
        CacheParameterGroupName=filled_name,
        CacheParameterGroupFamily="redis7",
        Description="a real, non-empty description",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=filled_name))

    by_name = {
        g["CacheParameterGroupName"]: g
        for n in (empty_name, filled_name)
        for g in ec.describe_cache_parameter_groups(CacheParameterGroupName=n)["CacheParameterGroups"]
    }

    assert empty_name in by_name, f"{empty_name} missing from DescribeCacheParameterGroups"
    # ElastiCache does not preserve an explicit empty-string Description: it coerces "" to a
    # single space " " server-side.
    assert by_name[empty_name]["Description"] == " ", (
        f"explicit empty-string Description round-tripped as {by_name[empty_name]['Description']!r}, "
        f"expected the real-AWS-observed coercion to ' ' (single space)"
    )

    assert filled_name in by_name, f"{filled_name} missing from DescribeCacheParameterGroups"
    assert by_name[filled_name]["Description"] == "a real, non-empty description", (
        f"non-empty Description round-tripped as {by_name[filled_name]['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
