"""tag-resource-list-untag-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-untag-roundtrip"
GROUP = 'tags'
SERVICES = ['codecommit']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource → ListTagsForResource → UntagResource round-trip on a repo ARN."""
    cc = ctx.client("codecommit")
    meta = cc.create_repository(repositoryName=ctx.unique_name("sim2real-behav-repo-"))["repositoryMetadata"]
    ctx.on_cleanup(lambda n=meta["repositoryName"]: cc.delete_repository(repositoryName=n))
    arn = meta["Arn"]
    key = ctx.unique_name("sim2real-behav-tagkey-")

    cc.tag_resource(resourceArn=arn, tags={key: "engineering"})
    tags = cc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get(key) == "engineering", tags

    cc.untag_resource(resourceArn=arn, tagKeys=[key])
    tags_after = cc.list_tags_for_resource(resourceArn=arn)["tags"]
    assert key not in tags_after, tags_after

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
