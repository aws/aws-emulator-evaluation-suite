"""create-schema-duplicate-name-rejected-bad-request."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-schema-duplicate-name-rejected-bad-request"
GROUP = "overly-permissive"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-CreateSchema on an existing name is rejected as ConflictException, leaving version 1 intact."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags=_mgmt_tags())
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    original_content = _openapi3_content("Widget")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=original_content,
        Tags=_mgmt_tags(),
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))

    err = _error(
        lambda: schemas.create_schema(
            RegistryName=registry,
            SchemaName=schema_name,
            Type="OpenApi3",
            Content=_openapi3_content("Widget", {"extra": {"type": "string"}}),
        )
    )
    assert err["Code"] == "ConflictException", f"unexpected error: {err!r}"
    assert err["Message"] == f"Schema with name {schema_name} already exists.", f"unexpected create_schema_dup message: {err['Message']!r}"

    unaffected = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert unaffected["SchemaVersion"] == "1", f"version advanced after rejected duplicate create: {unaffected['SchemaVersion']!r}"
    assert json.loads(unaffected["Content"]) == json.loads(original_content), (
        f"content changed after rejected duplicate create: {unaffected['Content']!r}"
    )

    # Positive control: creating a genuinely new schema name in the same registry still works.
    other_name = ctx.unique_name("sim2real-schemas-sch2-")
    control = schemas.create_schema(
        RegistryName=registry,
        SchemaName=other_name,
        Type="OpenApi3",
        Content=_openapi3_content("Gizmo"),
        Tags=_mgmt_tags(),
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=other_name))
    assert control["SchemaVersion"] == "1", f"unexpected version for a genuinely new schema name: {control['SchemaVersion']!r}"


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-schemas"}


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
