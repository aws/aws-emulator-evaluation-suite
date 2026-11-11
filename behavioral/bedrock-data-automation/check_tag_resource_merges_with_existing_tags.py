"""tag-resource-merges-with-existing-tags."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "tag-resource-merges-with-existing-tags"
GROUP = "tagging"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = json.dumps(
    {
        "class": "Merge",
        "description": "tag-merge schema",
        "properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}},
    }
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two sequential TagResource calls with disjoint keys result in the UNION of both tag sets,
    not the second call replacing the first."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-bp-tagmerge")
    arn = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=_SCHEMA)["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))

    bda.tag_resource(resourceARN=arn, tags=[{"key": "team", "value": "platform"}])
    bda.tag_resource(resourceARN=arn, tags=[{"key": "env", "value": "staging"}])

    tags = {t["key"]: t["value"] for t in bda.list_tags_for_resource(resourceARN=arn)["tags"]}
    assert tags == {"team": "platform", "env": "staging"}, (
        f"expected union of both disjoint-key TagResource calls, got {tags}"
    )

    # A subsequent TagResource call with a NEW value for an EXISTING key overwrites just that key.
    bda.tag_resource(resourceARN=arn, tags=[{"key": "env", "value": "production"}])
    tags_after = {t["key"]: t["value"] for t in bda.list_tags_for_resource(resourceARN=arn)["tags"]}
    assert tags_after == {"team": "platform", "env": "production"}, (
        f"expected only 'env' to be overwritten and 'team' to persist, got {tags_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
