"""update-schema-new-content-increments-version."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "update-schema-new-content-increments-version"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchema with materially different Content mints version 2 with a later timestamp."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    content_v1 = _openapi3_content("Widget")
    created = schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=content_v1,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))
    assert created["SchemaVersion"] == "1", f"expected initial SchemaVersion '1', got {created['SchemaVersion']!r}"
    version_created_1 = created["VersionCreatedDate"]

    content_v2 = _openapi3_content("Widget", {"color": {"type": "string"}})
    updated = schemas.update_schema(
        RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content=content_v2
    )
    assert updated["SchemaVersion"] == "2", (
        f"expected SchemaVersion '2' after updating with materially different content, "
        f"got {updated['SchemaVersion']!r}"
    )
    assert updated["VersionCreatedDate"] >= version_created_1, (
        f"expected version 2's VersionCreatedDate ({updated['VersionCreatedDate']}) to be >= "
        f"version 1's ({version_created_1})"
    )

    latest = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert latest["SchemaVersion"] == "2", (
        f"expected describe_schema (independent read) to report latest SchemaVersion '2', "
        f"got {latest['SchemaVersion']!r}"
    )
    assert json.loads(latest["Content"]) == json.loads(content_v2), (
        f"expected describe_schema's latest Content to match the updated content, got {latest['Content']}"
    )


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
