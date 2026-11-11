"""get-component-recipe-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-component-recipe-round-trip"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetComponent returns the exact recipe content that was submitted at creation."""
    ggv2 = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-comp-")
    marker = ctx.unique_name("sim2real-marker-")
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": "2.3.4",
        "ComponentDescription": marker,
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {"marker": marker}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }

    arn = ggv2.create_component_version(
        inlineRecipe=json.dumps(recipe).encode("utf-8"),
        tags={"sim2real-check": CHECK},
    )["arn"]
    ctx.on_cleanup(lambda: ggv2.delete_component(arn=arn))

    resp = ggv2.get_component(arn=arn)
    assert resp["recipeOutputFormat"] == "JSON", (
        f"expected default recipeOutputFormat JSON, got {resp['recipeOutputFormat']!r}"
    )
    fetched = json.loads(resp["recipe"])
    assert fetched["ComponentName"] == name, (
        f"expected ComponentName {name!r}, got {fetched.get('ComponentName')!r}"
    )
    assert fetched["ComponentVersion"] == "2.3.4", (
        f"expected ComponentVersion '2.3.4', got {fetched.get('ComponentVersion')!r}"
    )
    assert fetched["ComponentDescription"] == marker, (
        f"expected ComponentDescription {marker!r}, got {fetched.get('ComponentDescription')!r}"
    )
    assert fetched["ComponentConfiguration"]["DefaultConfiguration"]["marker"] == marker, (
        "expected DefaultConfiguration.marker "
        f"{marker!r}, got {fetched.get('ComponentConfiguration', {}).get('DefaultConfiguration', {}).get('marker')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
