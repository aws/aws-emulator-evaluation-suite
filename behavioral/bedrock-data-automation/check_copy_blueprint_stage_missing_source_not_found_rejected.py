"""copy-blueprint-stage-missing-source-not-found-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "copy-blueprint-stage-missing-source-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyBlueprintStage from a stage that has never been created (DEVELOPMENT, since CreateBlueprint
    without an explicit blueprintStage defaults to LIVE only) is rejected with ResourceNotFoundException
    and creates no DEVELOPMENT stage, while promoting from the stage that does exist (LIVE) succeeds."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bp-")
    schema = _blueprint_schema()
    created = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=schema,
        tags=[{"key": "purpose", "value": "sim2real"}],
    )["blueprint"]
    arn = created["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=arn))
    assert created["blueprintStage"] == "LIVE", f"expected LIVE default stage, got {created['blueprintStage']!r}"

    # DEVELOPMENT has never been created for this blueprint yet.
    code, message = _client_error(
        lambda: bda.copy_blueprint_stage(blueprintArn=arn, sourceStage="DEVELOPMENT", targetStage="LIVE")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} ({message})"
    assert message == "Blueprint Arn not found.", f"unexpected message: {message!r}"

    # Effect absent: DEVELOPMENT still does not exist.
    still_missing, missing_message = _client_error(
        lambda: bda.get_blueprint(blueprintArn=arn, blueprintStage="DEVELOPMENT")
    )
    assert still_missing == "ResourceNotFoundException", (
        f"expected DEVELOPMENT to remain absent (ResourceNotFoundException), got {still_missing!r}"
    )
    assert missing_message == "Blueprint Arn not found.", f"unexpected message: {missing_message!r}"

    # Positive control: copying from the stage that actually exists succeeds.
    bda.copy_blueprint_stage(blueprintArn=arn, sourceStage="LIVE", targetStage="DEVELOPMENT")
    dev = bda.get_blueprint(blueprintArn=arn, blueprintStage="DEVELOPMENT")["blueprint"]
    assert dev["blueprintStage"] == "DEVELOPMENT", f"expected DEVELOPMENT stage, got {dev['blueprintStage']!r}"
    got_schema, want_schema = json.loads(dev["schema"]), json.loads(schema)
    assert got_schema == want_schema, f"expected copied schema {want_schema}, got {got_schema}"


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


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
