"""list-images-owner-self-excludes-a-component-and-recipe-sharing-its-name."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-images-owner-self-excludes-a-component-and-recipe-sharing-its-name"
GROUP = "control-plane"
SERVICES = ["imagebuilder"]

_COMPONENT_DATA = """
name: sim2real-test-component
description: minimal test component for behavioral fidelity checks
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
    """ListImages(owner=Self) filtered by name returns nothing for a name a component and an
    image recipe hold; ListComponents and ListImageRecipes find them under that same name."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-")

    component_resp = ib.create_component(
        name=name,
        semanticVersion="1.0.0",
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    component_arn = component_resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=component_arn))

    parent_image = f"arn:aws:imagebuilder:{ctx.region}:aws:image/amazon-linux-2-x86/x.x.x"
    recipe_resp = ib.create_image_recipe(
        name=name,
        semanticVersion="1.0.0",
        parentImage=parent_image,
        components=[{"componentArn": component_arn}],
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    recipe_arn = recipe_resp["imageRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=recipe_arn))

    name_filter = [{"name": "name", "values": [name]}]

    # Measured: ListComponents and ListImageRecipes lag their creates by up to ~10s.
    listed_components = _poll(
        lambda: ib.list_components(owner="Self", filters=name_filter)["componentVersionList"],
        lambda v: len(v) > 0, description=f"component {name!r} listed",
    )
    assert {c["name"] for c in listed_components} == {name}, (
        f"expected ListComponents to report the component named {name!r}, got {listed_components!r}"
    )

    listed_recipes = _poll(
        lambda: ib.list_image_recipes(owner="Self", filters=name_filter)["imageRecipeSummaryList"],
        lambda v: len(v) > 0, description=f"image recipe {name!r} listed",
    )
    assert [r["arn"] for r in listed_recipes] == [recipe_arn], (
        f"expected ListImageRecipes to report only {recipe_arn!r}, got {listed_recipes!r}"
    )

    listed_images = ib.list_images(owner="Self", filters=name_filter)["imageVersionList"]
    assert listed_images == [], (
        f"expected ListImages to report no image for {name!r} (only a component and a recipe hold "
        f"that name), got {listed_images!r}"
    )


def _poll(probe, predicate, *, timeout_s=90.0, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result); return the result, raise AssertionError at deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
