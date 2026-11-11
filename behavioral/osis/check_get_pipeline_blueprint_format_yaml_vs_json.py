"""get-pipeline-blueprint-format-yaml-vs-json."""
from __future__ import annotations

import json

import yaml

from behavioral_harness import tags

CHECK = "get-pipeline-blueprint-format-yaml-vs-json"
GROUP = "blueprints"
SERVICES = ["osis"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPipelineBlueprint honors Format: Format=JSON returns a body that parses as JSON, Format=YAML returns
    a different body that does not, and both decode to the same structure, so the service renders one
    blueprint in each format.
    """
    osis = ctx.client("osis")
    listed = osis.list_pipeline_blueprints()["Blueprints"]
    assert listed, "ListPipelineBlueprints returned no blueprints"
    blueprint_name = listed[0]["BlueprintName"]

    json_resp = osis.get_pipeline_blueprint(BlueprintName=blueprint_name, Format="JSON")
    assert json_resp["Format"] == "JSON", f"expected Format echo 'JSON', got {json_resp['Format']!r}"
    json_body = json_resp["Blueprint"]["PipelineConfigurationBody"]
    parsed_json = json.loads(json_body)  # must not raise: this is the whole point of Format=JSON
    assert isinstance(parsed_json, dict), f"JSON-format body did not decode to a mapping: {json_body[:200]!r}"

    yaml_resp = osis.get_pipeline_blueprint(BlueprintName=blueprint_name, Format="YAML")
    assert yaml_resp["Format"] == "YAML", f"expected Format echo 'YAML', got {yaml_resp['Format']!r}"
    yaml_body = yaml_resp["Blueprint"]["PipelineConfigurationBody"]
    try:
        json.loads(yaml_body)
        is_json_too = True
    except (ValueError, TypeError):
        is_json_too = False
    assert not is_json_too, "YAML-format blueprint body should not also be valid JSON text"
    assert yaml_body.strip() != json_body.strip(), "YAML- and JSON-format bodies are byte-identical"

    parsed_yaml = yaml.safe_load(yaml_body)
    assert isinstance(parsed_yaml, dict), f"YAML-format body did not decode to a mapping: {yaml_body[:200]!r}"
    assert parsed_yaml == parsed_json, (
        f"YAML- and JSON-format bodies for {blueprint_name!r} decode to different structures "
        f"(yaml keys={sorted(parsed_yaml.keys())!r}, json keys={sorted(parsed_json.keys())!r}); "
        "the server should re-render the SAME blueprint, not different content per format"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
