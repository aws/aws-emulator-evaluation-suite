"""delete-blueprint-removes-resource."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-blueprint-removes-resource"
GROUP = "lifecycle-blueprint"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBlueprint permanently removes the Blueprint: a subsequent Get fails with
    ResourceNotFoundException, a mutation against the dead ARN fails the same way, and the
    freed blueprintName can be reused by a new Blueprint."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bp-")
    arn = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=_blueprint_schema(),
        tags=[{"key": "purpose", "value": "sim2real-delete-blueprint"}],
    )["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: _delete_if_present(bda, arn))

    # Sanity: it exists before delete.
    bda.get_blueprint(blueprintArn=arn)

    bda.delete_blueprint(blueprintArn=arn)

    code, message = _client_error(lambda: bda.get_blueprint(blueprintArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert message == "Blueprint Arn not found.", f"unexpected message: {message!r}"

    # The dead ARN is not just unreadable -- a mutation against it fails the same way.
    update_code, update_message = _client_error(
        lambda: bda.update_blueprint(blueprintArn=arn, schema=_blueprint_schema())
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on UpdateBlueprint against a deleted blueprint, got {update_code!r}"
    )
    assert update_message == "Blueprint Arn not found.", f"unexpected message: {update_message!r}"

    # The freed blueprintName is reusable -- DeleteBlueprint did not merely mark it gone.
    arn = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=_blueprint_schema())["blueprint"][
        "blueprintArn"
    ]
    reused = bda.get_blueprint(blueprintArn=arn)["blueprint"]
    assert reused["blueprintName"] == name, f"expected reused name {name!r}, got {reused['blueprintName']!r}"


def _delete_if_present(bda, arn):
    from botocore.exceptions import ClientError

    try:
        bda.delete_blueprint(blueprintArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
