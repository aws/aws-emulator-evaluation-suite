"""untag-resource-empty-tag-keys-validation-rejected."""
from __future__ import annotations

import json

from botocore.config import Config

from behavioral_harness import tags

CHECK = "untag-resource-empty-tag-keys-validation-rejected"
GROUP = "tagging"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with an empty tagKeys list, sent without client-side validation, is a no-op
    that keeps the existing tag, while untagging that key removes it.
    """
    ggv2 = ctx.client("greengrassv2")
    unvalidated = ctx.client("greengrassv2", config=Config(parameter_validation=False))
    name = ctx.unique_name("sim2real-ggv2-comp-")
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": "1.0.0",
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    arn = ggv2.create_component_version(inlineRecipe=json.dumps(recipe).encode("utf-8"))["arn"]
    ctx.on_cleanup(lambda: ggv2.delete_component(arn=arn))

    ggv2.tag_resource(resourceArn=arn, tags={"sim2real-key": "sim2real-value"})

    # The server treats an empty tagKeys list as a no-op: it returns 200, and the existing
    # tag is left untouched. (botocore's own client-side minLength=1 would block this call
    # before it ever reached the network on a normally-validated client.)
    unvalidated.untag_resource(resourceArn=arn, tagKeys=[])
    tags = ggv2.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-key") == "sim2real-value", tags

    # Positive control: untagging with a real, non-empty key list works.
    ggv2.untag_resource(resourceArn=arn, tagKeys=["sim2real-key"])
    tags_after = ggv2.list_tags_for_resource(resourceArn=arn).get("tags", {})
    assert "sim2real-key" not in tags_after, tags_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

