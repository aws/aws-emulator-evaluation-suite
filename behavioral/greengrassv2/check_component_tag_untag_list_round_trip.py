"""component-tag-untag-list-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "component-tag-untag-list-round-trip"
GROUP = "tagging"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a component version: tags
    applied are visible via ListTagsForResource and DescribeComponent, and removing them via
    UntagResource actually clears them rather than leaving stale entries."""
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-tag-")
    version = "1.0.0"
    resp = gg.create_component_version(inlineRecipe=_make_recipe(name, version))
    arn = resp["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, arn))

    gg.tag_resource(resourceArn=arn, tags={"env": "sim2real", "purpose": "behavioral-check"})
    tags_after_tag = gg.list_tags_for_resource(resourceArn=arn)["tags"]
    expected_after_tag = {"env": "sim2real", "purpose": "behavioral-check"}
    assert tags_after_tag == expected_after_tag, (
        f"expected {expected_after_tag}, got {tags_after_tag}"
    )

    described = gg.describe_component(arn=arn)
    assert described.get("tags") == expected_after_tag, (
        f"expected {expected_after_tag}, got {described.get('tags')}"
    )

    gg.untag_resource(resourceArn=arn, tagKeys=["purpose"])
    tags_after_untag = gg.list_tags_for_resource(resourceArn=arn)["tags"]
    expected_after_untag = {"env": "sim2real"}
    assert tags_after_untag == expected_after_untag, (
        f"expected {expected_after_untag}, got {tags_after_untag}"
    )


def _make_recipe(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "tag round-trip test",
        "ComponentPublisher": "sim2real",
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
