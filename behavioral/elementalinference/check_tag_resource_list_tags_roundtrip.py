"""tag-resource-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-roundtrip"
GROUP = "deploy"
SERVICES = ["elementalinference"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags set at CreateDictionary/CreateFeed come back unchanged, TagResource merges new tags without
    disturbing them, and UntagResource removes only the named keys."""
    ei = ctx.client("elementalinference")

    # Tags set at creation time, as a CloudFormation/IaC template would declare them.
    name = ctx.unique_name("sim2real-ei-dict-")
    resp = ei.create_dictionary(
        name=name, language="eng",
        entries='[{"content": "ace"}, {"content": "rally"}]',
        tags={"Environment": "sim2real-behav", "ManagedBy": "iac"},
    )
    dict_id = resp["id"]
    arn = resp["arn"]
    ctx.on_cleanup(lambda: ei.delete_dictionary(id=dict_id))

    assert resp.get("tags") == {"Environment": "sim2real-behav", "ManagedBy": "iac"}, resp.get("tags")
    tags = ei.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"Environment": "sim2real-behav", "ManagedBy": "iac"}, tags

    # A post-deploy TagResource call merges a new tag without disturbing the ones set at creation.
    ei.tag_resource(resourceArn=arn, tags={"env": "sim2real-behav"})
    tags = ei.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {
        "Environment": "sim2real-behav",
        "ManagedBy": "iac",
        "env": "sim2real-behav",
    }, f"TagResource should merge, not replace: {tags}"

    # UntagResource removes only the named key, leaving the rest of the deploy-time tag set intact.
    ei.untag_resource(resourceArn=arn, tagKeys=["env"])
    tags = ei.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"Environment": "sim2real-behav", "ManagedBy": "iac"}, f"tag still present after UntagResource: {tags}"

    # Same deploy-time-tags contract applies to the other taggable resource type (Feed).
    feed_name = ctx.unique_name("sim2real-ei-feed-")
    feed_resp = ei.create_feed(
        name=feed_name,
        outputs=[{"name": "sub1", "outputConfig": {"subtitling": {"language": "eng"}}, "status": "ENABLED"}],
        tags={"Environment": "sim2real-behav"},
    )
    feed_id = feed_resp["id"]
    feed_arn = feed_resp["arn"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))
    feed_tags = ei.list_tags_for_resource(resourceArn=feed_arn)["tags"]
    assert feed_tags == {"Environment": "sim2real-behav"}, feed_tags


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

