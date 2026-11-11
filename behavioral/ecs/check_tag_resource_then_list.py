"""tag-resource-then-list."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-then-list"
GROUP = 'tagging'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags that are then visible via ListTagsForResource; once the
    cluster is deleted, that same independent read stops finding the tags."""
    ecs = ctx.client("ecs")
    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    name = cluster["clusterName"]
    arn = cluster["clusterArn"]

    def _cleanup():
        try:
            ecs.delete_cluster(cluster=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    ecs.tag_resource(
        resourceArn=arn, tags=[{"key": "team", "value": "platform"}]
    )
    tags = ecs.list_tags_for_resource(resourceArn=arn)["tags"]
    kv = {t["key"]: t["value"] for t in tags}
    assert kv.get("team") == "platform", f"tag not visible after TagResource: {tags}"

    ecs.delete_cluster(cluster=name)
    # Empirically, ECS reports InvalidParameterException (not ClusterNotFoundException) for
    # ListTagsForResource against a cluster ARN that has just been deleted.
    error = _error(lambda: ecs.list_tags_for_resource(resourceArn=arn))
    expected = ("InvalidParameterException", "The specified cluster is inactive. Specify an active cluster and try again.")
    assert error == expected, f"expected {expected!r} after delete, got {error!r}"


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
