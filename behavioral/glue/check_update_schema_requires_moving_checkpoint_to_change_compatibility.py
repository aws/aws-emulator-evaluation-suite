"""update-schema-requires-moving-checkpoint-to-change-compatibility."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-schema-requires-moving-checkpoint-to-change-compatibility"
GROUP = "schema-compatibility-rejected"
SERVICES = ["glue"]

_RECORD_V1 = {
    "type": "record",
    "name": "Widget",
    "namespace": "com.example",
    "fields": [{"name": "id", "type": "string"}],
}
_RECORD_V2 = {
    "type": "record",
    "name": "Widget",
    "namespace": "com.example",
    "fields": [
        {"name": "id", "type": "string"},
        {"name": "note", "type": ["null", "string"], "default": None},
    ],
}

_NO_CHECKPOINT = ("InvalidInputException", "Schema version checkpoint is missing.")
_SAME_COMPATIBILITY = ("InvalidInputException", "Cannot update to the same compatibility setting.")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    actual = _error(fn)
    assert actual == (code, message), f"expected {(code, message)!r}, got {actual!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchema refuses a Compatibility change with no SchemaVersionNumber and refuses one
    to the current setting, leaving GetSchema unchanged; a later SchemaVersionNumber moves the
    checkpoint and applies the new Compatibility.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-glue-reg-")
    schema = ctx.unique_name("sim2real-behav-glue-sch-")
    schema_id = {"SchemaName": schema, "RegistryName": registry}

    glue.create_registry(RegistryName=registry)
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    created = glue.create_schema(
        SchemaName=schema,
        RegistryId={"RegistryName": registry},
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=json.dumps(_RECORD_V1),
    )
    ctx.on_cleanup(lambda: glue.delete_schema(SchemaId=schema_id))
    assert created["Compatibility"] == "BACKWARD", (
        f"expected BACKWARD at creation, got {created['Compatibility']!r}"
    )
    assert created["SchemaCheckpoint"] == 1, (
        f"expected checkpoint 1 at creation, got {created['SchemaCheckpoint']!r}"
    )

    registered = glue.register_schema_version(
        SchemaId=schema_id, SchemaDefinition=json.dumps(_RECORD_V2)
    )
    assert registered["VersionNumber"] == 2, (
        f"expected the added-optional-field version to register as 2, got {registered['VersionNumber']!r}"
    )

    expect_error(
        lambda: glue.update_schema(SchemaId=schema_id, Compatibility="FORWARD"),
        *_NO_CHECKPOINT,
    )
    after_first = glue.get_schema(SchemaId=schema_id)
    assert after_first["Compatibility"] == "BACKWARD", (
        f"a rejected update left Compatibility as {after_first['Compatibility']!r}, expected BACKWARD"
    )
    assert after_first["SchemaCheckpoint"] == 1, (
        f"a rejected update left SchemaCheckpoint as {after_first['SchemaCheckpoint']!r}, expected 1"
    )

    expect_error(
        lambda: glue.update_schema(
            SchemaId=schema_id,
            SchemaVersionNumber={"VersionNumber": 1},
            Compatibility="BACKWARD",
        ),
        *_SAME_COMPATIBILITY,
    )
    after_second = glue.get_schema(SchemaId=schema_id)
    assert after_second["Compatibility"] == "BACKWARD", (
        f"a rejected same-setting update left Compatibility as {after_second['Compatibility']!r}, "
        "expected BACKWARD"
    )
    assert after_second["SchemaCheckpoint"] == 1, (
        f"a rejected same-setting update left SchemaCheckpoint as {after_second['SchemaCheckpoint']!r}, "
        "expected 1"
    )

    updated = glue.update_schema(
        SchemaId=schema_id,
        SchemaVersionNumber={"VersionNumber": 2},
        Compatibility="FORWARD",
    )
    assert updated["SchemaName"] == schema, (
        f"expected SchemaName {schema!r} echoed back, got {updated['SchemaName']!r}"
    )
    assert updated["RegistryName"] == registry, (
        f"expected RegistryName {registry!r} echoed back, got {updated['RegistryName']!r}"
    )

    after_third = glue.get_schema(SchemaId=schema_id)
    assert after_third["Compatibility"] == "FORWARD", (
        f"a successful update left Compatibility as {after_third['Compatibility']!r}, expected FORWARD"
    )
    assert after_third["SchemaCheckpoint"] == 2, (
        f"a successful update left SchemaCheckpoint as {after_third['SchemaCheckpoint']!r}, expected 2"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
