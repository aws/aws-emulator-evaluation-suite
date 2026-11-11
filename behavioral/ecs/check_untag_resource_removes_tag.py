"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = 'tagging'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes a previously attached tag."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    ctx.on_cleanup(lambda c=cluster: ecs.delete_cluster(cluster=c["clusterName"]))
    arn = cluster["clusterArn"]

    ecs.tag_resource(resourceArn=arn, tags=[{"key": "temp", "value": "x"}])

    before = ecs.list_tags_for_resource(resourceArn=arn)["tags"]
    before_keys = [t["key"] for t in before]
    assert "temp" in before_keys, f"tag 'temp' should be present before untag, got {before}"

    ecs.untag_resource(resourceArn=arn, tagKeys=["temp"])

    tags = ecs.list_tags_for_resource(resourceArn=arn)["tags"]
    keys = [t["key"] for t in tags]
    assert "temp" not in keys, f"tag 'temp' should have been removed, got {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
