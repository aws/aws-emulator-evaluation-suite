"""create-schema-creates-version-one."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-schema-creates-version-one"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSchema always mints SchemaVersion "1" and DescribeSchema reflects it exactly."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry)
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    content = _openapi3_content("Widget")
    resp = schemas.create_schema(
        RegistryName=registry, SchemaName=schema_name, Type="OpenApi3", Content=content
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))

    assert resp["SchemaVersion"] == "1", f"expected SchemaVersion '1' from CreateSchema, got {resp['SchemaVersion']!r}"

    described = schemas.describe_schema(RegistryName=registry, SchemaName=schema_name)
    assert described["SchemaVersion"] == "1", (
        f"expected SchemaVersion '1' from independent DescribeSchema read, got {described['SchemaVersion']!r}"
    )
    described_content = json.loads(described["Content"])
    expected_content = json.loads(content)
    assert described_content == expected_content, (
        f"DescribeSchema content diverged from what CreateSchema was given: "
        f"expected {expected_content!r}, got {described_content!r}"
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
