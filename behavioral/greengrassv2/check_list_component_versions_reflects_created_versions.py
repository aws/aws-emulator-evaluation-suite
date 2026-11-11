"""list-component-versions-reflects-created-versions."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-component-versions-reflects-created-versions"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListComponentVersions returns every version created for a component, greatest first."""
    ggv2 = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-comp-")
    tags_kv = {"sim2real-key": "sim2real-value"}

    arn_a = ggv2.create_component_version(
        inlineRecipe=json.dumps(_recipe(name, "1.0.0")).encode("utf-8"), tags=tags_kv
    )["arn"]
    ctx.on_cleanup(lambda: ggv2.delete_component(arn=arn_a))
    arn_b = ggv2.create_component_version(
        inlineRecipe=json.dumps(_recipe(name, "1.0.1")).encode("utf-8"), tags=tags_kv
    )["arn"]
    ctx.on_cleanup(lambda: ggv2.delete_component(arn=arn_b))

    # ListComponentVersions takes the *component* ARN (no ":versions:<n>" suffix);
    # CreateComponentVersion's response "arn" is scoped to the version.
    component_arn = arn_a.rsplit(":versions:", 1)[0]
    resp = ggv2.list_component_versions(arn=component_arn)
    versions = [v["componentVersion"] for v in resp["componentVersions"]]
    assert set(versions) == {"1.0.0", "1.0.1"}, f"expected both versions, saw {versions}"
    # Documented contract: "Greater versions are listed first."
    assert versions.index("1.0.1") < versions.index("1.0.0"), (
        f"expected 1.0.1 before 1.0.0 (greatest first), saw order {versions}"
    )
    arns = {v["arn"] for v in resp["componentVersions"]}
    assert arns == {arn_a, arn_b}, f"expected version arns {{{arn_a}, {arn_b}}}, saw {arns}"


def _recipe(name: str, version: str) -> dict:
    return {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
