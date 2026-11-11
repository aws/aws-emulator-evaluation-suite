"""delete-registry-nonempty-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-registry-nonempty-rejected"
GROUP = "overly-permissive"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRegistry on a registry that still contains a schema is rejected; an empty registry deletes cleanly."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry)

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    schemas.create_schema(
        RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content=_openapi3_content("Widget")
    )

    def _final_cleanup():
        try:
            schemas.delete_schema(RegistryName=registry, SchemaName=schema_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        try:
            schemas.delete_registry(RegistryName=registry)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_final_cleanup)

    err = _error(lambda: schemas.delete_registry(RegistryName=registry))
    assert err["Code"] == "ConflictException", f"expected ConflictException deleting nonempty registry, got {err!r}"
    assert err["Message"] == "The registry you tried to delete is not empty.", f"unexpected delete_registry_nonempty message: {err['Message']!r}"

    still_there = schemas.describe_registry(RegistryName=registry)
    assert still_there["RegistryName"] == registry, (
        f"expected {registry} to still exist after the rejected delete, got {still_there!r}"
    )
    still_has_schema = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert still_has_schema["SchemaVersion"] == "1", (
        f"expected {schema_name} version '1' to survive the rejected delete, got {still_has_schema.get('SchemaVersion')!r}"
    )

    # Restore: remove the blocking schema, then the identical DeleteRegistry call must now succeed.
    schemas.delete_schema(RegistryName=registry, SchemaName=schema_name)
    schemas.delete_registry(RegistryName=registry)
    gone = _error(lambda: schemas.describe_registry(RegistryName=registry))
    assert gone["Code"] == "NotFoundException", (
        f"expected {registry} gone once DeleteRegistry succeeded on the now-empty registry, got {gone!r}"
    )
    assert gone["Message"] == f"Registry with name {registry} does not exist.", f"unexpected describe_registry_deleted message: {gone['Message']!r}"

    # Positive control: an independent, never-nonempty registry deletes without complaint too.
    empty_registry = ctx.unique_name("sim2real-schemas-empty-")
    schemas.create_registry(RegistryName=empty_registry)

    def _cleanup_empty_registry():
        try:
            schemas.delete_registry(RegistryName=empty_registry)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_empty_registry)
    schemas.delete_registry(RegistryName=empty_registry)
    gone_empty = _error(lambda: schemas.describe_registry(RegistryName=empty_registry))
    assert gone_empty["Code"] == "NotFoundException", (
        f"expected {empty_registry} gone after DeleteRegistry on an always-empty registry, got {gone_empty!r}"
    )
    assert gone_empty["Message"] == f"Registry with name {empty_registry} does not exist.", f"unexpected describe_registry_deleted_empty message: {gone_empty['Message']!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _openapi3_content(title: str) -> str:
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {"schemas": {"Event": {"type": "object", "properties": {"id": {"type": "string"}}}}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
