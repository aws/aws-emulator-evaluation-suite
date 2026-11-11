"""tag-propagation-server-side."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-propagation-server-side"
GROUP = "server-side"
SERVICES = ["bedrock-agent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource tags are immediately visible via ListTagsForResource, and
    UntagResource fully (not partially) removes them server-side."""
    bedrock = ctx.client("bedrock-agent")

    prompt = bedrock.create_prompt(name=ctx.unique_name("sim2real-prompt-tags-"))
    prompt_arn = prompt["arn"]
    ctx.on_cleanup(lambda: bedrock.delete_prompt(promptIdentifier=prompt_arn))

    initial_tags = bedrock.list_tags_for_resource(resourceArn=prompt_arn)["tags"]
    assert initial_tags == {}, f"expected no tags on a freshly created prompt, got {initial_tags!r}"

    bedrock.tag_resource(resourceArn=prompt_arn, tags={"Env": "sim2real", "Team": "qa"})
    tags_after_tag = bedrock.list_tags_for_resource(resourceArn=prompt_arn)["tags"]
    assert tags_after_tag == {"Env": "sim2real", "Team": "qa"}, (
        f"expected {{'Env': 'sim2real', 'Team': 'qa'}} after TagResource, got {tags_after_tag!r}"
    )

    bedrock.untag_resource(resourceArn=prompt_arn, tagKeys=["Env"])
    tags_after_partial_untag = bedrock.list_tags_for_resource(resourceArn=prompt_arn)["tags"]
    assert tags_after_partial_untag == {"Team": "qa"}, (
        f"expected only 'Team' to survive a partial UntagResource(['Env']), got {tags_after_partial_untag!r}"
    )

    bedrock.untag_resource(resourceArn=prompt_arn, tagKeys=["Team"])
    tags_after_full_untag = bedrock.list_tags_for_resource(resourceArn=prompt_arn)["tags"]
    assert tags_after_full_untag == {}, (
        f"expected no tags after untagging every key, got {tags_after_full_untag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
