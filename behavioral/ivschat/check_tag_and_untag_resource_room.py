"""tag-and-untag-resource-room."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-room"
GROUP = "state"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource, and UntagResource removes
    exactly the requested keys while leaving the others intact."""
    ivschat = ctx.client("ivschat")
    created = ivschat.create_room(name=ctx.unique_name("sim2real-ivschat-room"))
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=arn))

    ivschat.tag_resource(resourceArn=arn, tags={"env": "sim2real", "keep": "me"})
    tags = ivschat.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"env": "sim2real", "keep": "me"}

    ivschat.untag_resource(resourceArn=arn, tagKeys=["env"])
    tags_after = ivschat.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after == {"keep": "me"}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
