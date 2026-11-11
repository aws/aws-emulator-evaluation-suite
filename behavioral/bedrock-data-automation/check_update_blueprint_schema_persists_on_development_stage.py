"""update-blueprint-schema-persists-on-development-stage."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-blueprint-schema-persists-on-development-stage"
GROUP = "lifecycle-blueprint"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBlueprint replaces the DEVELOPMENT-stage schema in place (old fields gone, new fields present)."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bp-")
    original_schema = _blueprint_schema(field="original_field")
    created = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=original_schema,
        blueprintStage="DEVELOPMENT",
        tags=[{"key": "purpose", "value": "sim2real"}],
    )["blueprint"]
    arn = created["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))
    assert created["blueprintStage"] == "DEVELOPMENT", (
        f"expected DEVELOPMENT on create, got {created['blueprintStage']!r}"
    )

    new_schema = _blueprint_schema(field="replacement_field")
    updated = bda.update_blueprint(blueprintArn=arn, blueprintStage="DEVELOPMENT", schema=new_schema)[
        "blueprint"
    ]
    updated_props = json.loads(updated["schema"])["properties"]
    assert "replacement_field" in updated_props, f"replacement_field missing from update response: {updated_props!r}"
    assert "original_field" not in updated_props, (
        f"original_field still present in update response (schema was merged, not replaced): {updated_props!r}"
    )

    fetched = bda.get_blueprint(blueprintArn=arn, blueprintStage="DEVELOPMENT")["blueprint"]
    fetched_props = json.loads(fetched["schema"])["properties"]
    assert "replacement_field" in fetched_props, f"replacement_field missing on independent read: {fetched_props!r}"
    assert "original_field" not in fetched_props, (
        f"original_field still present on independent read (update did not persist as a replace): {fetched_props!r}"
    )
    assert fetched["blueprintStage"] == "DEVELOPMENT", (
        f"expected DEVELOPMENT on independent read, got {fetched['blueprintStage']!r}"
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
