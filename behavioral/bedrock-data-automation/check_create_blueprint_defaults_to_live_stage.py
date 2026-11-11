"""create-blueprint-defaults-to-live-stage."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-blueprint-defaults-to-live-stage"
GROUP = "lifecycle-blueprint"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBlueprint without blueprintStage creates a LIVE blueprint (also in GetBlueprint), and
    with blueprintStage DEVELOPMENT creates a DEVELOPMENT blueprint that GetBlueprint returns for
    that stage.
    """
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bp-")
    resp = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=_blueprint_schema(),
        tags=[{"key": "purpose", "value": "sim2real"}],
    )
    blueprint = resp["blueprint"]
    arn = blueprint["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))

    assert blueprint["blueprintStage"] == "LIVE", f"expected LIVE, got {blueprint['blueprintStage']!r}"
    assert blueprint["blueprintName"] == name, f"expected {name!r}, got {blueprint['blueprintName']!r}"

    got = bda.get_blueprint(blueprintArn=arn)["blueprint"]
    assert got["blueprintStage"] == "LIVE", f"independent read: expected LIVE, got {got['blueprintStage']!r}"

    # Explicitly requesting DEVELOPMENT yields the other stage.
    dev_name = ctx.unique_name("sim2real-bp-dev-")
    dev_resp = bda.create_blueprint(
        blueprintName=dev_name,
        type="DOCUMENT",
        schema=_blueprint_schema(),
        blueprintStage="DEVELOPMENT",
        tags=[{"key": "purpose", "value": "sim2real"}],
    )["blueprint"]
    dev_arn = dev_resp["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=dev_arn))
    assert dev_resp["blueprintStage"] == "DEVELOPMENT", (
        f"expected DEVELOPMENT, got {dev_resp['blueprintStage']!r}"
    )

    # GetBlueprint with no blueprintStage defaults to LIVE, which does not exist for a
    # DEVELOPMENT-only blueprint (ResourceNotFoundException), so the stage is named explicitly.
    got_dev = bda.get_blueprint(blueprintArn=dev_arn, blueprintStage="DEVELOPMENT")["blueprint"]
    assert got_dev["blueprintStage"] == "DEVELOPMENT", (
        f"independent read: expected DEVELOPMENT, got {got_dev['blueprintStage']!r}"
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
