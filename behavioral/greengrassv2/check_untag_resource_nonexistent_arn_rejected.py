"""untag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource on a well-formed but nonexistent component version ARN is rejected with
    NotFoundException, while UntagResource on a real, tagged resource (the positive
    control) actually removes the tag."""
    gg = ctx.client("greengrassv2")

    account = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = (
        f"arn:aws:greengrass:{ctx.region}:{account}:components:"
        f"{ctx.unique_name('sim2real-gg-notaguntag-')}:versions:1.0.0"
    )
    code, message = _error_code(lambda: gg.untag_resource(resourceArn=bogus_arn, tagKeys=["env"]))
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent resourceArn, got code={code!r}"
    )
    assert message == "Resource was not found", f"expected message 'Resource was not found', got {message!r}"

    # positive control: untagging a real, tagged resource succeeds
    name = ctx.unique_name("sim2real-gg-realuntag-")
    created = gg.create_component_version(inlineRecipe=_recipe_bytes(name, "1.0.0"))
    arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, arn))
    gg.tag_resource(resourceArn=arn, tags={"env": "sim2real"})
    gg.untag_resource(resourceArn=arn, tagKeys=["env"])
    remaining = gg.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "env" not in remaining


def _recipe_bytes(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-test",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _safe_delete_component(ctx, arn: str) -> None:
    gg = ctx.client("greengrassv2")
    try:
        gg.delete_component(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
