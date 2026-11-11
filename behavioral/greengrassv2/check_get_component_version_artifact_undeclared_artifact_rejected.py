"""get-component-version-artifact-undeclared-artifact-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-component-version-artifact-undeclared-artifact-rejected"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetComponentVersionArtifact for an artifact name the recipe never declares raises
    ValidationException with the exact message, while GetComponent returns the version's recipe
    name and version.
    """
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-gg-artifact-")
    version = "1.0.0"
    created = gg.create_component_version(
        inlineRecipe=_recipe_bytes(name, version),
        tags={"sim2real-check": "create-component-version-reaches-deployable"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _safe_delete_component(ctx, arn))

    code, message = _error_code(
        lambda: gg.get_component_version_artifact(arn=arn, artifactName="does-not-exist.zip")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == f"Component ({name}:1.0.0) or Artifact (does-not-exist.zip) for account {ctx.account} does not exist", (
        f"expected the exact ValidationException message AWS returns, got {message!r}"
    )

    # positive control: the component version itself is real and its recipe is the one this check created
    recipe_resp = gg.get_component(arn=arn)
    recipe = json.loads(recipe_resp["recipe"])
    assert recipe["ComponentName"] == name, f"expected recipe for {name!r}, got {recipe!r}"
    assert recipe["ComponentVersion"] == version, (
        f"expected version {version!r}, got {recipe['ComponentVersion']!r}"
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
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call succeeded where a ClientError was expected: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
