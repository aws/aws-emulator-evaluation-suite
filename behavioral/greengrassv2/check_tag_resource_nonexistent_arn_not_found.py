"""tag-resource-nonexistent-arn-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource against a real component version succeeds (positive control), while the
    identical call against a well-formed but never-created component version ARN returns
    NotFoundException instead of silently creating a tag record."""
    gg = ctx.client("greengrassv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-ggv2-tagnf-")
    created = gg.create_component_version(inlineRecipe=_recipe_bytes(name, "1.0.0"))
    arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete_component(gg, arn))

    gg.tag_resource(resourceArn=arn, tags={"env": "sim2real-behavioral"})
    ok = gg.list_tags_for_resource(resourceArn=arn)["tags"]
    assert ok.get("env") == "sim2real-behavioral", ok

    missing_name = ctx.unique_name("sim2real-ggv2-missing-")
    missing_arn = (
        f"arn:aws:greengrass:{ctx.region}:{account_id}:components:{missing_name}:versions:1.0.0"
    )
    code, message = _client_error(lambda: gg.tag_resource(resourceArn=missing_arn, tags={"k": "v"}))
    assert code == "NotFoundException", f"got code={code!r}"
    assert message == "Resource was not found", f"got message={message!r}"


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


def _safe_delete_component(gg, arn: str) -> None:
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
