"""list-component-versions-malformed-arn-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-component-versions-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListComponentVersions with a malformed arn raises ValidationException with the exact message,
    while on a real component arn it lists version 1.0.0.
    """
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-malformedlist-")
    created = gg.create_component_version(
        inlineRecipe=_recipe_bytes(name, "1.0.0"), tags={"env": "sim2real-behavioral"}
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, arn))
    base_arn = arn.rsplit(":versions:", 1)[0]

    code, message = _error_code(lambda: gg.list_component_versions(arn="not-an-arn-at-all"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid Input: Component ARN not-an-arn-at-all is invalid"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    ok = gg.list_component_versions(arn=base_arn)["componentVersions"]
    assert any(v["componentVersion"] == "1.0.0" for v in ok), (
        f"expected version 1.0.0 for {base_arn!r} in {ok!r}"
    )


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
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
