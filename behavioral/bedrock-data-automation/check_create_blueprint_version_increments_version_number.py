"""create-blueprint-version-increments-version-number."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-blueprint-version-increments-version-number"
GROUP = "lifecycle-blueprint"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBlueprintVersion creates an immutable numbered snapshot; each successive call on the
    same blueprint assigns a version number exactly one greater than the previous snapshot."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bp-")
    schema = _blueprint_schema()
    created = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=schema)["blueprint"]
    arn = created["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))
    # CreateBlueprintVersion snapshots the LIVE stage, which is what CreateBlueprint defaults to.
    assert created["blueprintStage"] == "LIVE", f"expected LIVE stage, got {created['blueprintStage']!r}"

    first_version = bda.create_blueprint_version(blueprintArn=arn)["blueprint"]
    assert first_version["blueprintArn"] == arn, (
        f"expected blueprintArn {arn!r}, got {first_version['blueprintArn']!r}"
    )
    assert json.loads(first_version["schema"]) == json.loads(schema), "first version schema mismatch"
    first_num = int(first_version["blueprintVersion"])

    second_version = bda.create_blueprint_version(blueprintArn=arn)["blueprint"]
    second_num = int(second_version["blueprintVersion"])
    assert second_num == first_num + 1, f"expected version {first_num + 1}, got {second_num}"

    # Independent reads, by version, prove each numbered snapshot is a real, retrievable artifact
    # -- not merely an artifact of the mutating call's own response.
    v1_read = bda.get_blueprint(blueprintArn=arn, blueprintVersion=first_version["blueprintVersion"])[
        "blueprint"
    ]
    assert v1_read["blueprintVersion"] == first_version["blueprintVersion"], (
        f"expected version {first_version['blueprintVersion']!r}, got {v1_read['blueprintVersion']!r}"
    )
    assert json.loads(v1_read["schema"]) == json.loads(schema), "version 1 snapshot schema mismatch on read"

    v2_read = bda.get_blueprint(blueprintArn=arn, blueprintVersion=second_version["blueprintVersion"])[
        "blueprint"
    ]
    assert v2_read["blueprintVersion"] == second_version["blueprintVersion"], (
        f"expected version {second_version['blueprintVersion']!r}, got {v2_read['blueprintVersion']!r}"
    )

    # The DEVELOPMENT stage's current schema itself is untouched by versioning.
    current = bda.get_blueprint(blueprintArn=arn)["blueprint"]
    assert current["blueprintStage"] == "LIVE", f"expected LIVE stage, got {current['blueprintStage']!r}"
    assert json.loads(current["schema"]) == json.loads(schema), "current schema drifted from original"


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
