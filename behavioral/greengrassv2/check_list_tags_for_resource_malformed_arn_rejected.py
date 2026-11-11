"""list-tags-for-resource-malformed-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource rejects a resourceArn that doesn't match any greengrass resource ARN
    pattern at all (not just 'well-formed but nonexistent') with BadRequestException, while
    listing tags for a real, tagged component ARN (the positive control) returns the real tags."""
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-listtagsmalformed-")
    created = gg.create_component_version(inlineRecipe=_recipe_bytes(name, "1.0.0"))
    arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, arn))
    gg.tag_resource(resourceArn=arn, tags={"env": "sim2real-behavioral"})

    code, message = _error_code(lambda: gg.list_tags_for_resource(resourceArn="clearly-not-an-arn"))
    assert code == "BadRequestException", f"expected BadRequestException, got code={code!r}"
    expected = "Invalid input resource arn: bad syntax"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    ok = gg.list_tags_for_resource(resourceArn=arn)["tags"]
    assert ok.get("env") == "sim2real-behavioral", f"expected real tags to survive, got {ok!r}"


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
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
