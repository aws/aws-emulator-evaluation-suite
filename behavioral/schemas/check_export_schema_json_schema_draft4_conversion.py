"""export-schema-json-schema-draft4-conversion."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-schema-json-schema-draft4-conversion"
GROUP = "data-plane"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportSchema converts an AWS-managed schema to JSONSchemaDraft4, while for a manually created schema an invalid
    Type is refused with BadRequestException and JSONSchemaDraft4 with ForbiddenException (exact messages), leaving the
    schema's OpenApi3 content unchanged.
    """
    schemas = ctx.client("schemas")

    # Positive control: an AWS-managed schema is eligible for export, proving JSONSchemaDraft4 is a
    # recognized Type and that ExportSchema can succeed at all on this account.
    aws_registry_name, aws_schema_name = _find_aws_managed_schema(schemas)
    exported = schemas.export_schema(
        RegistryName=aws_registry_name, SchemaName=aws_schema_name, Type="JSONSchemaDraft4"
    )
    exported_doc = json.loads(exported["Content"])
    assert "draft-04" in exported_doc.get("$schema", ""), (
        f"AWS-managed schema export did not convert to draft-4: {exported_doc.get('$schema')!r}"
    )

    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    original_content = _openapi3_content("Widget")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=original_content,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))

    # An export Type value that isn't a recognized export target enum is rejected server-side.
    bad_type = _error(
        lambda: schemas.export_schema(RegistryName=registry, SchemaName=schema_name, Type="OpenApi3")
    )
    assert bad_type["Code"] == "BadRequestException", f"unexpected error for unsupported export Type: {bad_type!r}"
    assert bad_type["Message"] == (
        "1 validation error detected: Value 'OpenApi3' at 'type' failed to satisfy constraint: "
        "Member must satisfy enum value set: [JSONSchemaDraft4]"
    ), f"unexpected export_openapi3 message: {bad_type['Message']!r}"

    # A valid export Type is still refused for a schema that is neither discovered nor AWS-managed.
    forbidden = _error(
        lambda: schemas.export_schema(RegistryName=registry, SchemaName=schema_name, Type="JSONSchemaDraft4")
    )
    assert forbidden["Code"] == "ForbiddenException", f"unexpected error exporting a manual schema: {forbidden!r}"
    assert forbidden["Message"] == "You cannot export non discovered or non aws managed schemas.", f"unexpected export_draft4_manual message: {forbidden['Message']!r}"

    # Neither rejected export call mutated the stored schema.
    still_openapi3 = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert still_openapi3["Type"] == "OpenApi3"
    assert json.loads(still_openapi3["Content"]) == json.loads(original_content)


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _find_aws_managed_schema(schemas_client):
    registries = schemas_client.list_registries(Scope="AWS")["Registries"]
    assert registries, "no AWS-managed schema registries visible to this account"
    for reg in registries:
        registry_name = reg["RegistryName"]
        page = schemas_client.list_schemas(RegistryName=registry_name, Limit=1)["Schemas"]
        if page:
            return registry_name, page[0]["SchemaName"]
    raise AssertionError(f"no schema found in any AWS-managed registry: {[r['RegistryName'] for r in registries]!r}")


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
