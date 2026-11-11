"""get-pipeline-blueprint-matches-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-pipeline-blueprint-matches-list"
GROUP = "blueprints"
SERVICES = ["osis"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPipelineBlueprint for a name returned by ListPipelineBlueprints returns a
    Blueprint whose BlueprintName/DisplayName/Service/UseCase match the list entry, and
    it carries a non-empty PipelineConfigurationBody."""
    osis = ctx.client("osis")
    listed = osis.list_pipeline_blueprints()["Blueprints"]
    assert listed, "ListPipelineBlueprints returned no blueprints"
    entry = listed[0]

    fetched = osis.get_pipeline_blueprint(BlueprintName=entry["BlueprintName"])["Blueprint"]
    assert fetched["BlueprintName"] == entry["BlueprintName"], (
        f'expected BlueprintName {entry["BlueprintName"]!r}, got {fetched["BlueprintName"]!r}'
    )
    assert fetched["DisplayName"] == entry["DisplayName"], (
        f'expected DisplayName {entry["DisplayName"]!r}, got {fetched["DisplayName"]!r}'
    )
    assert fetched["Service"] == entry["Service"], (
        f'expected Service {entry["Service"]!r}, got {fetched["Service"]!r}'
    )
    assert fetched["UseCase"] == entry["UseCase"], (
        f'expected UseCase {entry["UseCase"]!r}, got {fetched["UseCase"]!r}'
    )
    assert fetched["PipelineConfigurationBody"].strip() != "", (
        "expected a non-empty PipelineConfigurationBody, got an empty/whitespace body"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
