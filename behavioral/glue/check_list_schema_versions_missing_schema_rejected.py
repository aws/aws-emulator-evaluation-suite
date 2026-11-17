"""list-schema-versions-missing-schema-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-schema-versions-missing-schema-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]

_V1 = {
    "type": "record",
    "name": "DeviceReading",
    "namespace": "com.example.telemetry",
    "fields": [{"name": "device_id", "type": "string"}],
}


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSchemaVersions refuses a SchemaName that does not exist in the registry with
    EntityNotFoundException and its exact message, naming the registry and schema queried.
    """
    glue = ctx.client("glue")
    registry = ctx.unique_name("sim2real-behav-registry-")
    glue.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry}))

    missing_schema = ctx.unique_name("sim2real-behav-missing-")
    _MISSING_SCHEMA = (
        "EntityNotFoundException",
        f"Schema is not found. RegistryName: {registry}, SchemaName: {missing_schema}, SchemaArn: null",
    )
    expect_error(
        lambda: glue.list_schema_versions(SchemaId={"RegistryName": registry, "SchemaName": missing_schema}),
        *_MISSING_SCHEMA,
    )

    # positive control: a schema that does exist in the same registry lists its one version
    present_schema = ctx.unique_name("sim2real-behav-present-")
    created = glue.create_schema(
        RegistryId={"RegistryName": registry},
        SchemaName=present_schema,
        DataFormat="AVRO",
        Compatibility="BACKWARD",
        SchemaDefinition=json.dumps(_V1),
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_schema(SchemaId={"RegistryName": registry, "SchemaName": present_schema}))

    page = glue.list_schema_versions(SchemaId={"RegistryName": registry, "SchemaName": present_schema})
    assert len(page["Schemas"]) == 1, f"expected exactly 1 entry for {present_schema!r}, got {page['Schemas']!r}"
    assert page["Schemas"][0]["SchemaVersionId"] == created["SchemaVersionId"], (
        f"expected version id {created['SchemaVersionId']!r}, got {page['Schemas'][0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
