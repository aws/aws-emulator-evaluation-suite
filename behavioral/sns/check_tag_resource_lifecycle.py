"""tag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "tag-resource-lifecycle"
GROUP = 'policy-and-tags'
SERVICES = ['sns']

def _create_topic(client, ctx, name, attributes=None, tags=None):
    """CreateTopic + register best-effort DeleteTopic cleanup; returns the TopicArn."""
    kwargs = {"Name": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["Tags"] = tags
    arn = client.create_topic(**kwargs)["TopicArn"]
    ctx.on_cleanup(lambda: client.delete_topic(TopicArn=arn))
    return arn

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes them."""
    ev = ctx.client("sns")
    topic_arn = _create_topic(ev, ctx, ctx.unique_name("sim2real-behav-sns-tags-"))
    ev.tag_resource(ResourceArn=topic_arn, Tags=[{"Key": "env", "Value": "fidelity"}])
    tags = {t["Key"]: t["Value"] for t in ev.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]}
    assert tags.get("env") == "fidelity", f"expected tag env=fidelity, got {tags}"
    ev.untag_resource(ResourceArn=topic_arn, TagKeys=["env"])
    tags_after = {t["Key"]: t["Value"] for t in ev.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]}
    assert "env" not in tags_after, f"expected tag 'env' removed, still present: {tags_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
