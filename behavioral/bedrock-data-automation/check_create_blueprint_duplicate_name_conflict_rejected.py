"""create-blueprint-duplicate-name-conflict-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-blueprint-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBlueprint with a blueprintName that already exists is rejected with ConflictException,
    leaving the original Blueprint's schema untouched; once the name is freed by deleting the
    original, the identical call succeeds."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bp-dup-")
    original_schema = _blueprint_schema(field="original_field")
    original = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=original_schema)["blueprint"]
    original_arn = original["blueprintArn"]
    ctx.on_cleanup(lambda: _delete_blueprint_if_present(bda, original_arn))

    conflicting_schema = _blueprint_schema(field="conflicting_field")
    error = _client_error(
        lambda: bda.create_blueprint(blueprintName=name, type="IMAGE", schema=conflicting_schema)
    )
    assert error.get("Code") == "ConflictException", (
        f"expected ConflictException for a duplicate blueprintName, got {error!r}"
    )
    assert error.get("Message") == "Blueprint name already exists.", f"unexpected message: {error!r}"

    # Effect absent: the original Blueprint's schema was not overwritten by the rejected attempt.
    still = bda.get_blueprint(blueprintArn=original_arn)["blueprint"]
    assert json.loads(still["schema"]) == json.loads(original_schema), (
        f"rejected create must not mutate the existing blueprint's schema; got {still['schema']!r}"
    )

    # Restore: freeing the name by deleting the original makes the identical call succeed.
    bda.delete_blueprint(blueprintArn=original_arn)
    restored = bda.create_blueprint(blueprintName=name, type="IMAGE", schema=conflicting_schema)["blueprint"]
    restored_arn = restored["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=restored_arn))
    fetched = bda.get_blueprint(blueprintArn=restored_arn)["blueprint"]
    assert fetched["blueprintName"] == name, (
        f"expected the restored create to use the freed name {name!r}, got {fetched['blueprintName']!r}"
    )
    assert json.loads(fetched["schema"]) == json.loads(conflicting_schema), (
        f"expected the restored blueprint to carry the previously-conflicting schema, got {fetched['schema']!r}"
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


def _delete_blueprint_if_present(bda, arn):
    from botocore.exceptions import ClientError

    try:
        bda.delete_blueprint(blueprintArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
