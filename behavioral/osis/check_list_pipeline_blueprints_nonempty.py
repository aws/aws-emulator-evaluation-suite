"""list-pipeline-blueprints-nonempty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-pipeline-blueprints-nonempty"
GROUP = "blueprints"
SERVICES = ["osis"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPipelineBlueprints returns the account-agnostic catalog of built-in
    blueprints with the documented fields populated (not just a bare BlueprintName)."""
    osis = ctx.client("osis")
    blueprints = osis.list_pipeline_blueprints()["Blueprints"]
    assert len(blueprints) > 0, "expected a non-empty built-in blueprint catalog, got none"
    for bp in blueprints:
        assert bp["BlueprintName"], f"blueprint missing BlueprintName: {bp}"
        assert bp["DisplayName"], f"blueprint {bp['BlueprintName']} missing DisplayName"
        assert bp["DisplayDescription"], f"blueprint {bp['BlueprintName']} missing DisplayDescription"
        assert bp["Service"], f"blueprint {bp['BlueprintName']} missing Service"
        assert bp["UseCase"], f"blueprint {bp['BlueprintName']} missing UseCase"
    names = [bp["BlueprintName"] for bp in blueprints]
    assert len(names) == len(set(names)), f"blueprint names should be unique, got {names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
