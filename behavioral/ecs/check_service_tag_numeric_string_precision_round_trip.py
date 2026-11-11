"""service-tag-numeric-string-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "service-tag-numeric-string-precision-round-trip"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value that is a long numeric string round-trips through TagResource /
    ListTagsForResource unchanged: no truncation, no leading-zero stripping, no coercion
    to a numeric type (which would lose precision beyond 2^53 or drop leading zeros)."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-ecs-numtag-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # 40-digit numeric string with a leading zero: exceeds any native integer precision
    # concern and would be visibly mangled by any int-based coercion or truncation.
    numeric_value = "0123456789012345678901234567890123456789"

    ecs.tag_resource(resourceArn=cluster_arn, tags=[{"key": "numericTag", "value": numeric_value}])

    listed = ecs.list_tags_for_resource(resourceArn=cluster_arn)
    tags = {t["key"]: t["value"] for t in listed.get("tags", [])}
    value = tags.get("numericTag")
    assert isinstance(value, str), f"tag value was not returned as a string: {type(value)!r}"
    assert value == numeric_value, f"numeric string tag value mangled: {value!r} != {numeric_value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
