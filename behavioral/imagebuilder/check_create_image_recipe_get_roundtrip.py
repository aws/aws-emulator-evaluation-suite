"""create-image-recipe-get-roundtrip."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-recipe-get-roundtrip"
GROUP = "control-plane"
SERVICES = ["imagebuilder"]

_COMPONENT_DATA = """
name: sim2real-test-component
description: minimal test component
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: HelloWorldStep
        action: ExecuteBash
        inputs:
          commands:
            - echo "hello world"
""".strip()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateImageRecipe persists the parentImage and component list exactly as submitted, and
    DeleteImageRecipe makes it unreachable and non-deletable again."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx, ib)

    recipe_name = ctx.unique_name("sim2real-recipe-")
    parent_image = f"arn:aws:imagebuilder:{ctx.region}:aws:image/amazon-linux-2-x86/x.x.x"
    resp = ib.create_image_recipe(
        name=recipe_name,
        semanticVersion="1.0.0",
        parentImage=parent_image,
        components=[{"componentArn": component_arn}],
        clientToken=str(uuid.uuid4()),
        tags={"purpose": "sim2real"},
    )
    recipe_arn = resp["imageRecipeArn"]
    ctx.on_cleanup(lambda: _safe_delete_image_recipe(ib, recipe_arn))

    got = ib.get_image_recipe(imageRecipeArn=recipe_arn)["imageRecipe"]
    assert got["arn"] == recipe_arn, f"expected arn {recipe_arn!r}, got {got['arn']!r}"
    assert got["name"] == recipe_name, f"expected name {recipe_name!r}, got {got['name']!r}"
    assert got["parentImage"] == parent_image, (
        f"expected parentImage {parent_image!r}, got {got['parentImage']!r}"
    )
    assert len(got["components"]) == 1, f"expected 1 component, got {len(got['components'])}"
    assert got["components"][0]["componentArn"] == component_arn, (
        f"expected component {component_arn!r}, got {got['components'][0]['componentArn']!r}"
    )

    ib.delete_image_recipe(imageRecipeArn=recipe_arn)
    code, msg = _error(lambda: ib.get_image_recipe(imageRecipeArn=recipe_arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetImageRecipe on deleted arn to be not-found, got {code!r}"
    )
    expected = f"The following required resource 'ImageRecipe' cannot be found: '{recipe_arn}'."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"
    code, msg = _error(lambda: ib.delete_image_recipe(imageRecipeArn=recipe_arn))
    assert code == "ResourceNotFoundException", (
        f"expected DeleteImageRecipe on already-deleted arn to be not-found, got {code!r}"
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _create_component(ctx, ib):
    name = ctx.unique_name("sim2real-component-")
    resp = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=str(uuid.uuid4()),
        tags={"purpose": "sim2real"},
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    return arn


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_image_recipe(ib, arn):
    try:
        ib.delete_image_recipe(imageRecipeArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
