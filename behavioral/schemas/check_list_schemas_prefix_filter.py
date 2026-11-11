"""list-schemas-prefix-filter."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "list-schemas-prefix-filter"
GROUP = "data-plane"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSchemas SchemaNamePrefix returns only schemas whose name starts with the given prefix."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    prefix = ctx.unique_name("sim2real-schemas-pfx-")
    matching_name = f"{prefix}-alpha"
    other_name = ctx.unique_name("sim2real-schemas-other-")

    schemas.create_schema(
        RegistryName=registry,
        SchemaName=matching_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget"),
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=matching_name))
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=other_name,
        Type="OpenApi3",
        Content=_openapi3_content("Gizmo"),
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=other_name))

    listed = schemas.list_schemas(RegistryName=registry, SchemaNamePrefix=prefix)
    names = {s["SchemaName"] for s in listed["Schemas"]}
    assert matching_name in names, f"expected {matching_name!r} in prefix-filtered list, got {names!r}"
    assert other_name not in names, f"expected {other_name!r} excluded from prefix-filtered list, got {names!r}"


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
