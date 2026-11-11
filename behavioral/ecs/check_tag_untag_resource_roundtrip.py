"""tag-untag-resource-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-untag-resource-roundtrip"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on an ECS cluster ARN."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    cluster = ecs.create_cluster(clusterName=name)["cluster"]
    arn = cluster["clusterArn"]

    def _cleanup():
        try:
            ecs.delete_cluster(cluster=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    ecs.tag_resource(resourceArn=arn, tags=[{"key": "sim2real-check", "value": "true"}])
    tags = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert tags.get("sim2real-check") == "true", f"expected tag to be present, got {tags}"

    ecs.untag_resource(resourceArn=arn, tagKeys=["sim2real-check"])
    tags_after = {t["key"]: t["value"] for t in ecs.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert "sim2real-check" not in tags_after, f"expected tag removed, got {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
