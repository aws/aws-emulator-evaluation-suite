"""list-schema-versions-reflects-all-versions."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-schema-versions-reflects-all-versions"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSchemaVersions enumerates every version created by CreateSchema + successive UpdateSchema calls."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget"),
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))
    schemas.update_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget", {"color": {"type": "string"}}),
    )
    schemas.update_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget", {"color": {"type": "string"}, "weight": {"type": "number"}}),
    )

    versions = schemas.list_schema_versions(RegistryName=registry, SchemaName=schema_name)
    entries = versions["SchemaVersions"]
    seen = {v["SchemaVersion"] for v in entries}
    assert seen == {"1", "2", "3"}, f"expected versions {{'1', '2', '3'}} from list_schema_versions, got {seen}"
    for entry in entries:
        assert entry["SchemaName"] == schema_name, f"expected SchemaName {schema_name!r}, got {entry['SchemaName']!r}"
        assert entry["Type"] == "OpenApi3", f"expected Type 'OpenApi3', got {entry['Type']!r}"


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
