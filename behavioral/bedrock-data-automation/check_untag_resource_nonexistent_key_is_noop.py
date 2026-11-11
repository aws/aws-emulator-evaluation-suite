"""untag-resource-nonexistent-key-is-noop."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-key-is-noop"
GROUP = "lifecycle"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = json.dumps(
    {
        "class": "Untag",
        "description": "untag-noop schema",
        "properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}},
    }
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a tagKey that was never applied to the resource succeeds as a no-op
    (idempotent removal), leaving the resource's existing tags untouched."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-bp-untag")
    arn = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=_SCHEMA)["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))

    bda.tag_resource(resourceARN=arn, tags=[{"key": "env", "value": "sim2real"}])

    # This key was never applied; removing it must not raise and must not touch "env".
    bda.untag_resource(resourceARN=arn, tagKeys=["never-applied-key"])

    tags = {t["key"]: t["value"] for t in bda.list_tags_for_resource(resourceARN=arn)["tags"]}
    assert tags == {"env": "sim2real"}, (
        f"expected only env=sim2real to survive UntagResource(never-applied-key), got {tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
