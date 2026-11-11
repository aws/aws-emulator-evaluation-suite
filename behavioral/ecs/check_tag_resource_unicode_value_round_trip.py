"""tag-resource-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-unicode-value-round-trip"
GROUP = "state-machine"
SERVICES = ["ecs"]

_UNICODE_TAG_VALUE = "日本語タグ値 héllo Ñoño Кириллица"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing multi-byte unicode characters survives a
    TagResource / ListTagsForResource round-trip unchanged."""
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-cluster-tagrt-")

    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    ecs.tag_resource(
        resourceArn=cluster_arn,
        tags=[{"key": "sim2real-unicode-tag", "value": _UNICODE_TAG_VALUE}],
    )

    tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    matching = [t for t in tags if t["key"] == "sim2real-unicode-tag"]
    assert len(matching) == 1, f"expected exactly one matching tag, found {matching}"
    assert matching[0]["value"] == _UNICODE_TAG_VALUE, (
        f"tag value mangled in round-trip: expected {_UNICODE_TAG_VALUE!r}, "
        f"got {matching[0]['value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
