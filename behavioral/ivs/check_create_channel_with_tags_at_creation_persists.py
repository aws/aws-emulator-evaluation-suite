"""create-channel-with-tags-at-creation-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-with-tags-at-creation-persists"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied directly on CreateChannel (not via a separate TagResource call)
    are durable and readable through both GetChannel and ListTagsForResource."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-createtags-")
    created = ivs.create_channel(
        name=name, tags={"team": "video", "stage": "test"}
    )["channel"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    assert created["tags"] == {"team": "video", "stage": "test"}, (
        f"CreateChannel response tags: expected "
        f"{{'team': 'video', 'stage': 'test'}}, got {created['tags']}"
    )

    refetched = ivs.get_channel(arn=arn)["channel"]
    assert refetched["tags"] == {"team": "video", "stage": "test"}, (
        f"GetChannel tags: expected {{'team': 'video', 'stage': 'test'}}, "
        f"got {refetched['tags']}"
    )

    via_list_tags = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    assert via_list_tags == {"team": "video", "stage": "test"}, (
        f"ListTagsForResource tags: expected "
        f"{{'team': 'video', 'stage': 'test'}}, got {via_list_tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
