"""tag-resource-non-greengrass-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-non-greengrass-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a valid ARN of another service raises BadRequestException with the exact
    message, while tagging a real component ARN shows the tag in ListTagsForResource.
    """
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-wrongarntype-")
    created = gg.create_component_version(inlineRecipe=_recipe_bytes(name, "1.0.0"))
    arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, arn))

    account = ctx.client("sts").get_caller_identity()["Account"]
    non_greengrass_arn = f"arn:aws:s3:::sim2real-not-a-greengrass-resource-{account}"
    code, message = _client_error(lambda: gg.tag_resource(resourceArn=non_greengrass_arn, tags={"env": "x"}))
    assert code == "BadRequestException", f"expected BadRequestException, got code={code!r}"
    expected = "Invalid input resource arn: expected vendor greengrass"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: tagging a real greengrass component ARN succeeds
    gg.tag_resource(resourceArn=arn, tags={"env": "sim2real-behavioral"})
    ok = gg.list_tags_for_resource(resourceArn=arn)["tags"]
    assert ok.get("env") == "sim2real-behavioral", f"expected tag to be visible, got {ok!r}"


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


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
