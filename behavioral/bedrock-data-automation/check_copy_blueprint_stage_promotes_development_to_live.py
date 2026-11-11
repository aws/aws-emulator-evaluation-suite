"""copy-blueprint-stage-promotes-development-to-live."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "copy-blueprint-stage-promotes-development-to-live"
GROUP = "lifecycle-blueprint"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyBlueprintStage(DEVELOPMENT->LIVE) makes the LIVE stage readable with the copied schema."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bp-")
    schema = _blueprint_schema()
    created = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=schema,
        blueprintStage="DEVELOPMENT",
        tags=[{"key": "purpose", "value": "sim2real"}],
    )["blueprint"]
    arn = created["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))
    assert created["blueprintStage"] == "DEVELOPMENT", (
        f"expected CreateBlueprint(blueprintStage=DEVELOPMENT) to create a DEVELOPMENT-stage "
        f"blueprint, got stage={created['blueprintStage']!r}"
    )

    bda.copy_blueprint_stage(blueprintArn=arn, sourceStage="DEVELOPMENT", targetStage="LIVE")

    live = bda.get_blueprint(blueprintArn=arn, blueprintStage="LIVE")["blueprint"]
    assert live["blueprintStage"] == "LIVE", (
        f"expected GetBlueprint(blueprintStage=LIVE) to succeed after CopyBlueprintStage "
        f"(DEVELOPMENT->LIVE), got stage={live['blueprintStage']!r}"
    )
    assert json.loads(live["schema"]) == json.loads(schema), (
        f"expected the LIVE stage schema to be an exact copy of the DEVELOPMENT schema, "
        f"got live={live['schema']!r} vs source={schema!r}"
    )

    # DEVELOPMENT stage is unaffected by the copy.
    dev = bda.get_blueprint(blueprintArn=arn, blueprintStage="DEVELOPMENT")["blueprint"]
    assert dev["blueprintStage"] == "DEVELOPMENT", (
        f"expected the source DEVELOPMENT stage to still exist and report its own stage after "
        f"the copy, got stage={dev['blueprintStage']!r}"
    )
    assert json.loads(dev["schema"]) == json.loads(schema), (
        f"expected the DEVELOPMENT stage's schema to be unchanged by CopyBlueprintStage, "
        f"got dev={dev['schema']!r} vs source={schema!r}"
    )


def _blueprint_schema(class_name: str = "SimparityTestDoc", field: str = "test_field") -> str:
    return json.dumps(
        {
            "class": class_name,
            "description": "Simparity behavioral fidelity test blueprint",
            "properties": {
                field: {
                    "type": "string",
                    "inferenceType": "explicit",
                    "instruction": "Extract the test field value",
                }
            },
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
