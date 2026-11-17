"""schema-definition-max-length-boundary."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "schema-definition-max-length-boundary"
GROUP = "schema-definition"
SERVICES = ["glue"]

_BASE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "InventoryAdjustment",
    "type": "object",
    "properties": {
        "adjustmentId": {"type": "string"},
        "quantityDelta": {"type": "integer"},
    },
    "required": ["adjustmentId", "quantityDelta"],
}


def _schema_json_of_length(target_len: int) -> str:
    """A JSON Schema document serialized to exactly `target_len` characters.

    The padding lives in an unused property's `description`, so the structural content is
    identical at every size and only the padding changes.
    """
    doc = json.loads(json.dumps(_BASE_SCHEMA))
    doc["properties"]["_filler"] = {"type": "string", "description": ""}
    baseline = json.dumps(doc)
    pad_len = target_len - len(baseline)
    assert pad_len >= 0, f"target {target_len} is shorter than the unpadded baseline {len(baseline)}"
    doc["properties"]["_filler"]["description"] = "f" * pad_len
    out = json.dumps(doc)
    assert len(out) == target_len, f"built {len(out)} chars, wanted {target_len}"
    return out


def expect_error(fn, code: str, message: str) -> None:
    """Asserts fn() raises a ClientError with exactly (code, message); an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_code, got_message = err.get("Code"), err.get("Message")
        assert got_code == code, f"expected code {code!r}, got {got_code!r}: {got_message!r}"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; the resource's own
    not-found codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchema accepts a 170000-char SchemaDefinition and stores it byte-for-byte, and
    rejects a 170001-char one with InvalidInputException, leaving its name unreadable.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-glue-reg-")
    glue.create_registry(RegistryName=registry)
    ctx.on_cleanup(_teardown(
        lambda: glue.delete_registry(RegistryId={"RegistryName": registry}), "EntityNotFoundException"
    ))

    at_limit_name = ctx.unique_name("sim2real-behav-glue-sch-atlimit-")
    at_limit_definition = _schema_json_of_length(170000)
    created = glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=at_limit_name,
        DataFormat="JSON",
        Compatibility="NONE",
        SchemaDefinition=at_limit_definition,
    )
    ctx.on_cleanup(_teardown(
        lambda: glue.delete_schema(SchemaId={"RegistryName": registry, "SchemaName": at_limit_name}),
        "EntityNotFoundException",
    ))
    assert created["SchemaName"] == at_limit_name, f"expected {at_limit_name!r}, got {created['SchemaName']!r}"

    stored = glue.get_schema_version(
        SchemaId={"RegistryName": registry, "SchemaName": at_limit_name},
        SchemaVersionNumber={"LatestVersion": True},
    )
    assert stored["SchemaDefinition"] == at_limit_definition, (
        f"stored definition differs from the 170000-char one sent "
        f"(stored {len(stored['SchemaDefinition'])} chars, sent {len(at_limit_definition)})"
    )

    over_limit_name = ctx.unique_name("sim2real-behav-glue-sch-overlimit-")
    over_limit_definition = _schema_json_of_length(170001)
    _TOO_LONG = (
        "InvalidInputException",
        "The resource name contains too many or too few characters. Parameter Name: schemaDefinition",
    )
    expect_error(
        lambda: glue.create_schema(
            RegistryId={"RegistryName": registry},
            SchemaName=over_limit_name,
            DataFormat="JSON",
            Compatibility="NONE",
            SchemaDefinition=over_limit_definition,
        ),
        *_TOO_LONG,
    )

    _NAME_UNREADABLE = (
        "EntityNotFoundException",
        f"Schema is not found. RegistryName: {registry}, SchemaName: {over_limit_name}, SchemaArn: null",
    )
    expect_error(
        lambda: glue.get_schema(SchemaId={"RegistryName": registry, "SchemaName": over_limit_name}),
        *_NAME_UNREADABLE,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
