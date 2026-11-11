"""delete-last-schema-version-removes-schema."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-last-schema-version-removes-schema"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSchemaVersion refuses to remove a schema's only remaining version (ConflictException, schema

    survives intact) but succeeds on that same version once it is no longer the last one; DeleteSchema
    is the only path that removes a schema's final version.
    """
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"Owner": "sim2real"})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget"),
        Tags={"Owner": "sim2real"},
    )

    def _cleanup_schema_if_present():
        try:
            schemas.delete_schema(RegistryName=registry, SchemaName=schema_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_schema_if_present)

    schemas.update_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget", {"a": {"type": "string"}}),
    )

    # Positive control: with two versions present, version "1" is not the last one, so deleting it
    # is the ordinary, unremarkable case. Without this, "refuses to delete version 1" would be
    # indistinguishable from "DeleteSchemaVersion always fails".
    schemas.delete_schema_version(RegistryName=registry, SchemaName=schema_name, SchemaVersion="1")
    versions = schemas.list_schema_versions(RegistryName=registry, SchemaName=schema_name)
    remaining = {v["SchemaVersion"] for v in versions["SchemaVersions"]}
    assert remaining == {"2"}, f"expected only version 2 to remain after deleting version 1, got {remaining!r}"

    # Break exactly one thing: version "2" is now the schema's only remaining version.
    err = _error(
        lambda: schemas.delete_schema_version(RegistryName=registry, SchemaName=schema_name, SchemaVersion="2")
    )
    assert err["Code"] == "ConflictException", f"expected ConflictException deleting the sole remaining version, got {err!r}"
    assert err["Message"] == (
        "Cannot delete all versions of a Schema. To delete a Schema use the DeleteSchema API."
    ), f"unexpected delete_last_version message: {err['Message']!r}"

    still_there = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert still_there["SchemaVersion"] == "2", (
        f"version 2 must survive the refused delete; describe_schema reported version {still_there['SchemaVersion']!r}"
    )

    # Restore: adding a third version means "2" is no longer the last version, so the identical
    # DeleteSchemaVersion(SchemaVersion="2") call must now succeed.
    schemas.update_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget", {"b": {"type": "string"}}),
    )
    schemas.delete_schema_version(RegistryName=registry, SchemaName=schema_name, SchemaVersion="2")
    versions_after_restore = schemas.list_schema_versions(RegistryName=registry, SchemaName=schema_name)
    remaining_after_restore = {v["SchemaVersion"] for v in versions_after_restore["SchemaVersions"]}
    assert remaining_after_restore == {"3"}, (
        f"expected only version 3 to remain after the restored delete of version 2, got {remaining_after_restore!r}"
    )

    # DeleteSchema (the whole-resource operation) removes the schema and its last version together.
    schemas.delete_schema(RegistryName=registry, SchemaName=schema_name)

    gone = _error(lambda: schemas.describe_schema(RegistryName=registry, SchemaName=schema_name))
    assert gone["Code"] == "NotFoundException", f"describe_schema must report the schema not-found after DeleteSchema, got {gone!r}"
    assert gone["Message"] == f"Schema with name {schema_name} does not exist.", f"unexpected describe_schema_deleted message: {gone['Message']!r}"

    listed = schemas.list_schemas(RegistryName=registry)
    listed_names = {s["SchemaName"] for s in listed["Schemas"]}
    assert schema_name not in listed_names, (
        f"deleted schema {schema_name!r} still appears in list_schemas: {listed_names!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _openapi3_content(title: str, extra_props: dict | None = None) -> str:
    props = {"id": {"type": "string"}}
    if extra_props:
        props.update(extra_props)
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {"schemas": {"Event": {"type": "object", "properties": props}}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
