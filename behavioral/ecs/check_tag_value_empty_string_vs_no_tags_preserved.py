"""tag-value-empty-string-vs-no-tags-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-empty-string-vs-no-tags-preserved"
GROUP = "representation"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicit empty-string tag value round-trips as a present tag with value "".

    It is distinct from an untagged resource and from a key that was never tagged.
    """
    ecs = ctx.client("ecs")
    cluster_name = ctx.unique_name("sim2real-cluster-tagempty-")

    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_arn))

    # Before any TagResource call, the resource must have no tags at all.
    pre_tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    assert pre_tags == [], f"expected a freshly created cluster to have no tags, got {pre_tags}"

    empty_key = "sim2real-empty-value"
    nonempty_key = "sim2real-nonempty-value"
    never_set_key = "sim2real-never-set-value"
    ecs.tag_resource(
        resourceArn=cluster_arn,
        tags=[{"key": empty_key, "value": ""}, {"key": nonempty_key, "value": "present"}],
    )

    post_tags = ecs.list_tags_for_resource(resourceArn=cluster_arn)["tags"]
    by_key = {t["key"]: t.get("value") for t in post_tags}
    assert len(by_key) == 2, f"expected exactly the two tags just written, got {by_key}"
    assert empty_key in by_key and by_key[empty_key] == "", (
        f"expected explicit empty-string tag value to be preserved as a present, empty value; "
        f"got {by_key}"
    )
    assert by_key.get(nonempty_key) == "present", (
        f"expected the ordinary non-empty tag to round-trip unchanged; got {by_key}"
    )
    assert never_set_key not in by_key, (
        f"expected a key that was never tagged to be genuinely absent, not collapsed with the "
        f"empty-value tag; got {by_key}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
