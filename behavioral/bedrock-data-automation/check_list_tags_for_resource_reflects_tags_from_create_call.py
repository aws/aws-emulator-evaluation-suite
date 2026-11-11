"""list-tags-for-resource-reflects-tags-from-create-call."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-tags-for-resource-reflects-tags-from-create-call"
GROUP = "tagging"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = json.dumps(
    {
        "class": "InlineTags",
        "description": "inline-tags schema",
        "properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}},
    }
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied inline via CreateBlueprint's `tags` parameter are visible immediately via
    ListTagsForResource, with no separate TagResource call needed."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-bp-inlinetags")
    arn = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=_SCHEMA,
        tags=[{"key": "created-with", "value": "inline-tags"}, {"key": "purpose", "value": "sim2real"}],
    )["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))

    listed = {t["key"]: t["value"] for t in bda.list_tags_for_resource(resourceARN=arn)["tags"]}
    expected = {"created-with": "inline-tags", "purpose": "sim2real"}
    assert listed == expected, f"expected tags {expected} reflected from create call, got {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
